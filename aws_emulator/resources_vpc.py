import uuid
from core import AWSResource

class Vpc(AWSResource):
    def __init__(self, cidr, owner_id="123456789012"):
        super().__init__("vpc")
        self.cidr = cidr; self.state = "available"; self.is_default = "false"
        self.dhcp_opts = "dopt-default"; self.tenancy = "default"
        self.owner_id = owner_id
        self.cidr_assoc_id = f"vpc-cidr-assoc-{uuid.uuid4().hex[:8]}"
    def to_xml(self):
        cidr_assoc = f"""<cidrBlockAssociationSet><item><cidrBlock>{self.cidr}</cidrBlock><associationId>{self.cidr_assoc_id}</associationId><cidrBlockState><state>associated</state></cidrBlockState></item></cidrBlockAssociationSet>"""
        return f"""<vpcId>{self.id}</vpcId><ownerId>{self.owner_id}</ownerId><state>{self.state}</state><cidrBlock>{self.cidr}</cidrBlock>{cidr_assoc}<ipv6CidrBlockAssociationSet/><dhcpOptionsId>{self.dhcp_opts}</dhcpOptionsId><instanceTenancy>{self.tenancy}</instanceTenancy><isDefault>{self.is_default}</isDefault>{self.render_tags()}"""

class Subnet(AWSResource):
    def __init__(self, vpc_id, cidr, map_public_ip="false"):
        super().__init__("subnet")
        self.vpc_id = vpc_id; self.cidr = cidr
        self.az = "us-east-1a"; self.available_ips = "251"
        self.map_public_ip = map_public_ip
    def to_xml(self):
        return f"""<subnetId>{self.id}</subnetId><vpcId>{self.vpc_id}</vpcId><cidrBlock>{self.cidr}</cidrBlock><availabilityZone>{self.az}</availabilityZone><availableIpAddressCount>{self.available_ips}</availableIpAddressCount><state>available</state><mapPublicIpOnLaunch>{self.map_public_ip}</mapPublicIpOnLaunch>{self.render_tags()}"""

class SecurityGroup(AWSResource):
    def __init__(self, vpc_id, name, desc, owner_id="123456789012"):
        super().__init__("sg")
        self.vpc_id = vpc_id; self.name = name; self.desc = desc
        self.owner_id = owner_id
        self.ingress = []
        # Real AWS seeds every new security group with an allow-all egress rule.
        self.egress = [self._new_rule("-1", None, None, "0.0.0.0/0")]

    def _new_rule(self, protocol, from_port, to_port, cidr):
        return {
            "id": f"sgr-{uuid.uuid4().hex[:8]}",
            "p": protocol, "f": from_port, "t": to_port, "c": cidr,
        }

    def add_ingress(self, protocol, from_port, to_port, cidr):
        rule = self._new_rule(protocol, from_port, to_port, cidr)
        self.ingress.append(rule)
        return rule

    def add_egress(self, protocol, from_port, to_port, cidr):
        rule = self._new_rule(protocol, from_port, to_port, cidr)
        self.egress.append(rule)
        return rule

    def _render_permissions(self, rules):
        items = "".join([
            f"<item><ipProtocol>{r['p']}</ipProtocol>"
            + (f"<fromPort>{r['f']}</fromPort><toPort>{r['t']}</toPort>" if r['f'] is not None else "")
            + "<groups/>"
            + (f"<ipRanges><item><cidrIp>{r['c']}</cidrIp></item></ipRanges>" if r['c'] else "<ipRanges/>")
            + "<prefixListIds/></item>"
            for r in rules
        ])
        return items

    def to_xml(self):
        ingress_xml = self._render_permissions(self.ingress)
        egress_xml = self._render_permissions(self.egress)
        return f"""<ownerId>{self.owner_id}</ownerId><groupId>{self.id}</groupId><groupName>{self.name}</groupName><groupDescription>{self.desc}</groupDescription><vpcId>{self.vpc_id}</vpcId><ipPermissions>{ingress_xml}</ipPermissions><ipPermissionsEgress>{egress_xml}</ipPermissionsEgress>{self.render_tags()}"""

    def rules_xml(self):
        """Renders the flat securityGroupRuleSet shape used by DescribeSecurityGroupRules."""
        def rule_item(r, egress):
            return (
                f"<item><securityGroupRuleId>{r['id']}</securityGroupRuleId><groupId>{self.id}</groupId>"
                f"<groupOwnerId>{self.owner_id}</groupOwnerId><isEgress>{'true' if egress else 'false'}</isEgress>"
                f"<ipProtocol>{r['p']}</ipProtocol>"
                + (f"<fromPort>{r['f']}</fromPort><toPort>{r['t']}</toPort>" if r['f'] is not None else "")
                + (f"<cidrIpv4>{r['c']}</cidrIpv4>" if r['c'] else "")
                + "</item>"
            )
        items = "".join([rule_item(r, False) for r in self.ingress]) + "".join([rule_item(r, True) for r in self.egress])
        return items

class NetworkAcl(AWSResource):
    def __init__(self, vpc_id, is_default="false"):
        super().__init__("acl")
        self.vpc_id = vpc_id; self.is_default = is_default
    def to_xml(self):
        entry = f"<item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>"
        entry += f"<item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>"
        return f"""<networkAclId>{self.id}</networkAclId><vpcId>{self.vpc_id}</vpcId><default>{self.is_default}</default><entrySet>{entry}</entrySet>{self.render_tags()}"""

class RouteTable(AWSResource):
    def __init__(self, vpc_id, is_main="false"):
        super().__init__("rtb")
        self.vpc_id = vpc_id; self.is_main = is_main
        self.routes = [] 
    def to_xml(self):
        routes_xml = f"<item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId><state>active</state><origin>CreateRouteTable</origin></item>"
        assoc_xml = f"<item><routeTableAssociationId>rtbassoc-default</routeTableAssociationId><routeTableId>{self.id}</routeTableId><main>{self.is_main}</main></item>"
        return f"""<routeTableId>{self.id}</routeTableId><vpcId>{self.vpc_id}</vpcId><routeSet>{routes_xml}</routeSet><associationSet>{assoc_xml}</associationSet>{self.render_tags()}"""