package aws

import (
	"fmt"
	"time"

	awsgo "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
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

func GetEc2ServiceClient(region string) ec2iface.EC2API {
	return ec2.New(newSession(region))
}

type Vpc struct {
	Region string
	VpcId  string
	svc    ec2iface.EC2API
}

// NewVpcPerRegion returns a Vpc for each enabled region
func NewVpcPerRegion(regions []string) ([]Vpc, error) {
	var vpcs []Vpc
	for _, region := range regions {
		vpc := Vpc{
			svc:    GetEc2ServiceClient(region),
			Region: region,
		}
		vpcs = append(vpcs, vpc)
	}
	return vpcs, nil
}

func GetDefaultVpcId(vpc Vpc) (string, error) {
	input := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   awsgo.String("isDefault"),
				Values: []*string{awsgo.String("true")},
			},
		},
	}
	vpcs, err := vpc.svc.DescribeVpcs(input)
	if err != nil {
		logging.Logger.Errorf("[Failed] %s", err)
		return "", errors.WithStackTrace(err)
	}
	if len(vpcs.Vpcs) == 1 {
		return awsgo.StringValue(vpcs.Vpcs[0].VpcId), nil
	} else if len(vpcs.Vpcs) > 1 {
		// More than one VPC in a region should never happen
		err = fmt.Errorf("Impossible - more than one VPC found in region %s", vpc.Region)
		return "", errors.WithStackTrace(err)
	}
	// No default VPC
	return "", nil
}

func GetDefaultVpcs(vpcs []Vpc) ([]Vpc, error) {
	for i := 0; i < len(vpcs); i++ {
		vpcId, err := GetDefaultVpcId(vpcs[i])
		if err != nil {
			return []Vpc{Vpc{}}, errors.WithStackTrace(err)
		}
		if vpcId != "" {
			vpcs[i].VpcId = vpcId
		} else {
			// Ignore regions that don't have a default VPC
			vpcs = append(vpcs[:i], vpcs[i+1:]...)
			i--
		}
	}
	return vpcs, nil
}

func (v Vpc) nukeInternetGateway() error {
	input := &ec2.DescribeInternetGatewaysInput{
		Filters: []*ec2.Filter{
			{
				Name:   awsgo.String("attachment.vpc-id"),
				Values: []*string{awsgo.String(v.VpcId)},
			},
		},
	}
	igw, err := v.svc.DescribeInternetGateways(input)
	if err != nil {
		return errors.WithStackTrace(err)
	}

	if len(igw.InternetGateways) == 1 {
		logging.Logger.Infof("...detaching Internet Gateway %s", awsgo.StringValue(igw.InternetGateways[0].InternetGatewayId))
		_, err := v.svc.DetachInternetGateway(
			&ec2.DetachInternetGatewayInput{
				InternetGatewayId: igw.InternetGateways[0].InternetGatewayId,
				VpcId:             awsgo.String(v.VpcId),
			},
		)
		if err != nil {
			return errors.WithStackTrace(err)
		}

		logging.Logger.Infof("...deleting Internet Gateway %s", awsgo.StringValue(igw.InternetGateways[0].InternetGatewayId))
		_, err = v.svc.DeleteInternetGateway(
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

func (v Vpc) nukeSubnets() error {
	subnets, _ := v.svc.DescribeSubnets(
		&ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(v.VpcId)},
				},
			},
		},
	)
	if len(subnets.Subnets) > 0 {
		for _, subnet := range subnets.Subnets {
			logging.Logger.Infof("...deleting subnet %s", awsgo.StringValue(subnet.SubnetId))
			_, err := v.svc.DeleteSubnet(
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

func (v Vpc) nukeRouteTables() error {
	routeTables, _ := v.svc.DescribeRouteTables(
		&ec2.DescribeRouteTablesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(v.VpcId)},
				},
			},
		},
	)
	for _, routeTable := range routeTables.RouteTables {
		// Skip main route table
		if len(routeTable.Associations) > 0 && *routeTable.Associations[0].Main {
			continue
		}

		logging.Logger.Infof("...deleting route table %s", awsgo.StringValue(routeTable.RouteTableId))
		_, err := v.svc.DeleteRouteTable(
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

func (v Vpc) nukeNacls() error {
	networkACLs, _ := v.svc.DescribeNetworkAcls(
		&ec2.DescribeNetworkAclsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("default"),
					Values: []*string{awsgo.String("false")},
				},
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(v.VpcId)},
				},
			},
		},
	)
	for _, networkACL := range networkACLs.NetworkAcls {
		logging.Logger.Infof("...deleting Network ACL %s", awsgo.StringValue(networkACL.NetworkAclId))
		_, err := v.svc.DeleteNetworkAcl(
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

func (v Vpc) nukeSecurityGroups() error {
	securityGroups, _ := v.svc.DescribeSecurityGroups(
		&ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   awsgo.String("vpc-id"),
					Values: []*string{awsgo.String(v.VpcId)},
				},
			},
		},
	)
	for _, securityGroup := range securityGroups.SecurityGroups {
		logging.Logger.Infof("...deleting Security Group %s", awsgo.StringValue(securityGroup.GroupId))
		if *securityGroup.GroupName != "default" {
			_, err := v.svc.DeleteSecurityGroup(
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

func (v Vpc) nukeVpc() error {
	logging.Logger.Infof("...deleting VPC %s", v.VpcId)
	input := &ec2.DeleteVpcInput{
		VpcId: awsgo.String(v.VpcId),
	}
	_, err := v.svc.DeleteVpc(input)
	if err != nil {
		return errors.WithStackTrace(err)
	}
	return nil
}

func (v Vpc) nuke() error {
	logging.Logger.Infof("Nuking VPC %s in region %s", v.VpcId, v.Region)

	err := v.nukeInternetGateway()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Internet Gateway for VPC %s: %s", v.VpcId, err.Error())
		return err
	}

	err = v.nukeSubnets()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Subnets for VPC %s: %s", v.VpcId, err.Error())
		return err
	}

	err = v.nukeRouteTables()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Route Tables for VPC %s: %s", v.VpcId, err.Error())
		return err
	}

	err = v.nukeNacls()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Network ACLs for VPC %s: %s", v.VpcId, err.Error())
		return err
	}

	err = v.nukeSecurityGroups()
	if err != nil {
		logging.Logger.Errorf("Error cleaning up Security Groups for VPC %s: %s", v.VpcId, err.Error())
		return err
	}

	err = v.nukeVpc()
	if err != nil {
		logging.Logger.Infof("Unable to delete VPC %s. Skipping to the next default VPC.", v.VpcId)
		return err
	}
	return nil
}

// Deletes all default VPCs
func NukeVpcs(vpcs []Vpc) error {
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

type DefaultSecurityGroup struct {
	GroupName string
	GroupId   string
	Region    string
	svc       ec2iface.EC2API
}

func GetDefaultSgs(regions []string) ([]DefaultSecurityGroup, error) {
	var sgs []DefaultSecurityGroup
	for _, region := range regions {
		sg := DefaultSecurityGroup{
			svc:       GetEc2ServiceClient(region),
			Region:    region,
			GroupName: "default",
		}

		securityGroups, err := sg.svc.DescribeSecurityGroups(
			&ec2.DescribeSecurityGroupsInput{
				GroupNames: []*string{awsgo.String("default")},
			},
		)
		if err != nil {
			return []DefaultSecurityGroup{}, errors.WithStackTrace(err)
		}
		for _, group := range securityGroups.SecurityGroups {
			sg.GroupId = awsgo.StringValue(group.GroupId)
		}

		sgs = append(sgs, sg)
	}
	return sgs, nil
}

func (sg DefaultSecurityGroup) nuke() error {
	logging.Logger.Infof("Nuking Security Group %s in region %s", sg.GroupId, sg.Region)

	logging.Logger.Infof("...deleting Security Group %s", sg.GroupId)
	if sg.GroupName == "default" {
		_, err := sg.svc.DeleteSecurityGroup(
			&ec2.DeleteSecurityGroupInput{
				GroupId: awsgo.String(sg.GroupId),
			},
		)
		if err != nil {
			return errors.WithStackTrace(err)
		}
	}
	return nil
}

// Deletes all default security groups for a given region
func NukeDefaultSecurityGroups(sgs []DefaultSecurityGroup) error {
	for _, sg := range sgs {
		err := sg.nuke()
		if err != nil {
			logging.Logger.Errorf("Error: %s", err)
			logging.Logger.Error("Skipping to the next default Security Group")
			continue
		}
	}
	logging.Logger.Info("Finished nuking default Security Groups in all regions")
	return nil
}
