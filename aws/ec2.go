package aws

import (
	"time"

	awsgo "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gruntwork-io/cloud-nuke/logging"
	"github.com/gruntwork-io/gruntwork-cli/errors"
)

// returns only instance Ids of unprotected ec2 instances
func filterOutProtectedInstances(svc *ec2.EC2, output *ec2.DescribeInstancesOutput, excludeAfter time.Time) ([]*string, error) {
	var filteredIds []*string
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			instanceID := *instance.InstanceId

			attr, err := svc.DescribeInstanceAttribute(&ec2.DescribeInstanceAttributeInput{
				Attribute:  awsgo.String("disableApiTermination"),
				InstanceId: awsgo.String(instanceID),
			})

			if err != nil {
				return nil, errors.WithStackTrace(err)
			}

			protected := *attr.DisableApiTermination.Value
			// Exclude protected EC2 instances
			if !protected {
				if excludeAfter.After(*instance.LaunchTime) {
					filteredIds = append(filteredIds, &instanceID)
				}
			}
		}
	}

	return filteredIds, nil
}

// Returns a formatted string of EC2 instance ids
func getAllEc2Instances(session *session.Session, region string, excludeAfter time.Time) ([]*string, error) {
	svc := ec2.New(session)

	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name: awsgo.String("instance-state-name"),
				Values: []*string{
					awsgo.String("running"), awsgo.String("pending"),
					awsgo.String("stopped"), awsgo.String("stopping"),
				},
			},
		},
	}

	output, err := svc.DescribeInstances(params)
	if err != nil {
		return nil, errors.WithStackTrace(err)
	}

	instanceIds, err := filterOutProtectedInstances(svc, output, excludeAfter)
	if err != nil {
		return nil, errors.WithStackTrace(err)
	}

	return instanceIds, nil
}

// Deletes all non protected EC2 instances
func nukeAllEc2Instances(session *session.Session, instanceIds []*string) error {
	svc := ec2.New(session)

	if len(instanceIds) == 0 {
		logging.Logger.Infof("No EC2 instances to nuke in region %s", *session.Config.Region)
		return nil
	}

	logging.Logger.Infof("Terminating all EC2 instances in region %s", *session.Config.Region)

	params := &ec2.TerminateInstancesInput{
		InstanceIds: instanceIds,
	}

	_, err := svc.TerminateInstances(params)
	if err != nil {
		logging.Logger.Errorf("[Failed] %s", err)
		return errors.WithStackTrace(err)
	}

	err = svc.WaitUntilInstanceTerminated(&ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   awsgo.String("instance-id"),
				Values: instanceIds,
			},
		},
	})

	for _, instanceID := range instanceIds {
		logging.Logger.Infof("Terminated EC2 Instance: %s", *instanceID)
	}

	if err != nil {
		logging.Logger.Errorf("[Failed] %s", err)
		return errors.WithStackTrace(err)
	}

	logging.Logger.Infof("[OK] %d instance(s) terminated in %s", len(instanceIds), *session.Config.Region)
	return nil
}

func getDefaultVpc(region string) (DefaultVpc, error) {
	svc := ec2.New(newSession(region))
	input := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   awsgo.String("isDefault"),
				Values: []*string{awsgo.String("true")},
			},
		},
	}
	vpcs, err := svc.DescribeVpcs(input)
	if err != nil {
		logging.Logger.Errorf("[Failed] %s", err)
		return DefaultVpc{}, errors.WithStackTrace(err)
	}
	if len(vpcs.Vpcs) == 1 {
		return DefaultVpc{
			Region: region,
			VpcId:  awsgo.StringValue(vpcs.Vpcs[0].VpcId),
		}, nil
	}
	return DefaultVpc{}, nil
}

func GetDefaultVpcByRegion() ([]DefaultVpc, error) {
	var defaultVpcs []DefaultVpc

	regions, err := GetEnabledRegions()
	if err != nil {
		logging.Logger.Errorf("[Failed] %s", err)
		return nil, errors.WithStackTrace(err)
	}

	for _, region := range regions {
		vpc, err := getDefaultVpc(region)
		if err != nil {
			return nil, errors.WithStackTrace(err)
		}
		if vpc != (DefaultVpc{}) {
			defaultVpcs = append(defaultVpcs, vpc)
		}
	}
	return defaultVpcs, nil
}

type DefaultVpc struct {
	Region string
	VpcId  string
	svc    *ec2.EC2
}

func (dv DefaultVpc) nukeInternetGateway() error {
	input := &ec2.DescribeInternetGatewaysInput{
		Filters: []*ec2.Filter{
			{
				Name:   awsgo.String("attachment.vpc-id"),
				Values: []*string{awsgo.String(dv.VpcId)},
			},
		},
	}
	igw, err := dv.svc.DescribeInternetGateways(input)
	if err != nil {
		return errors.WithStackTrace(err)
	}

	if len(igw.InternetGateways) == 1 {
		logging.Logger.Infof("...detaching Internet Gateway %s", awsgo.StringValue(igw.InternetGateways[0].InternetGatewayId))
		_, err := dv.svc.DetachInternetGateway(
			&ec2.DetachInternetGatewayInput{
				InternetGatewayId: igw.InternetGateways[0].InternetGatewayId,
				VpcId:             awsgo.String(dv.VpcId),
			},
		)
		if err != nil {
			return errors.WithStackTrace(err)
		}

		logging.Logger.Infof("...deleting Internet Gateway %s", awsgo.StringValue(igw.InternetGateways[0].InternetGatewayId))
		_, err = dv.svc.DeleteInternetGateway(
			&ec2.DeleteInternetGatewayInput{
				InternetGatewayId: igw.InternetGateways[0].InternetGatewayId,
			},
		)
		if err != nil {
			return errors.WithStackTrace(err)
		}
	}

	return nil
}

func (dv DefaultVpc) nukeSubnets() error {
	subnets, _ := dv.svc.DescribeSubnets(
		&ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(dv.VpcId)},
				},
			},
		},
	)
	if len(subnets.Subnets) > 0 {
		for _, subnet := range subnets.Subnets {
			logging.Logger.Infof("...deleting subnet %s", awsgo.StringValue(subnet.SubnetId))
			_, err := dv.svc.DeleteSubnet(
				&ec2.DeleteSubnetInput{
					SubnetId: subnet.SubnetId,
				},
			)
			if err != nil {
				return errors.WithStackTrace(err)
			}
		}
	}
	return nil
}

func (dv DefaultVpc) nukeRouteTables() error {
	routeTables, _ := dv.svc.DescribeRouteTables(
		&ec2.DescribeRouteTablesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(dv.VpcId)},
				},
			},
		}
	)
	for _, routeTable := range routeTables.RouteTables {
		// Skip route table of type main
		if len(routeTable.Associations) > 0 && *routeTable.Associations[0].Main {
			continue
		}

		logging.Logger.Infof("...deleting route table %s", awsgo.StringValue(routeTable.RouteTableId))
		_, err := dv.svc.DeleteRouteTable(
			&ec2.DeleteRouteTableInput{
				RouteTableId: routeTable.RouteTableId,
			},
		)
		if err != nil {
			return errors.WithStackTrace(err)
		}
	}
	return nil
}

func (dv DefaultVpc) nukeNacls() error {
	networkACLs, _ := dv.svc.DescribeNetworkAcls(
		&ec2.DescribeNetworkAclsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("default"),
					Values: []*string{awsgo.String("false")},
				},
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(dv.VpcId)},
				},
			},
		},
	)
	for _, networkACL := range networkACLs.NetworkAcls {
		logging.Logger.Infof("...deleting Network ACL %s", awsgo.StringValue(networkACL.NetworkAclId))
		_, err := dv.svc.DeleteNetworkAcl(
			&ec2.DeleteNetworkAclInput{
				NetworkAclId: networkACL.NetworkAclId,
			},
		)
		if err != nil {
			return errors.WithStackTrace(err)
		}
	}
	return nil
}

func (dv DefaultVpc) nukeSecurityGroups() error {
	securityGroups, _ := dv.svc.DescribeSecurityGroups(
		&ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(dv.VpcId)},
				},
			},
		},
	)
	for _, securityGroup := range securityGroups.SecurityGroups {
		logging.Logger.Infof("...deleting Security Group %s", awsgo.StringValue(securityGroup.GroupId))
		if *securityGroup.GroupName != "default" {
			_, err := dv.svc.DeleteSecurityGroup(
				&ec2.DeleteSecurityGroupInput{
					GroupId: securityGroup.GroupId,
				},
			)
			if err != nil {
				return errors.WithStackTrace(err)
			}
		}
	}
	return nil
}

func (dv DefaultVpc) nukeVpc() error {
	logging.Logger.Infof("...deleting VPC %s", dv.VpcId)
	input := &ec2.DeleteVpcInput{
		VpcId: awsgo.String(dv.VpcId),
	}
	_, err := dv.svc.DeleteVpc(input)
	if err != nil {
		return errors.WithStackTrace(err)
	}
	return nil
}

func (dv DefaultVpc) nuke() error {
	logging.Logger.Infof("Nuking VPC %s in region %s", dv.VpcId, dv.Region)
	dv.svc = ec2.New(newSession(dv.Region))

	err := dv.nukeInternetGateway()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Internet Gateway for VPC %s: %s", dv.VpcId, err.Error())
		return err
	}

	err = dv.nukeSubnets()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Subnets for VPC %s: %s", dv.VpcId, err.Error())
		return err
	}

	err = dv.nukeRouteTables()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Route Tables for VPC %s: %s", dv.VpcId, err.Error())
		return err
	}

	err = dv.nukeNacls()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Network ACLs for VPC %s: %s", dv.VpcId, err.Error())
		return err
	}

	err = dv.nukeSecurityGroups()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Security Groups for VPC %s: %s", dv.VpcId, err.Error())
		return err
	}

	err = dv.nukeVpc()
	if err != nil {
		logging.Logger.Infof("Unable to delete VPC %s. Skipping to the next default VPC.", dv.VpcId)
		return err
	}
	return nil
}

// Deletes all default VPCs
func NukeDefaultVpcs(vpcs []DefaultVpc) error {
	for _, vpc := range vpcs {
		err := vpc.nuke()
		if err != nil {
			logging.Logger.Errorf("Skipping to the next default VPC")
			continue
		}
	}
	logging.Logger.Info("Finished nuking default VPCs in all regions")
	return nil
}
