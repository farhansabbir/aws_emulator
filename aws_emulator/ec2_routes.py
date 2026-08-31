"""EC2/VPC query-protocol action handlers (mode: ec2, all).

Extracted from the original monolithic main.py dispatch chain. Each handler
returns a Flask Response; dispatch(action, req) returns None if the action
isn't an EC2/VPC action, so the caller can fall through to IAM/STS dispatch.
"""
import uuid
from flask import Response
from core import XML
from ec2_backend import backend
from resources_vpc import SecurityGroup

def _xml(action, content):
    return Response(XML.wrap(action, content), mimetype="text/xml")


def dispatch(action, req):
    # --- VPC ---
    if action == "CreateVpc":
        vpc = backend.create_vpc(req.get("CidrBlock"))
        tags = req.get_tag_specifications("vpc")
        if tags:
            vpc.add_tags(tags)
        return _xml(action, f"<vpc>{vpc.to_xml()}</vpc>")

    if action == "DescribeVpcs":
        vid = req.get_filter("vpc-id")
        objs = [backend.vpcs[vid]] if vid and vid in backend.vpcs else list(backend.vpcs.values())
        return _xml(action, XML.dump_list("vpcSet", objs))

    if action == "DescribeVpcAttribute":
        vpc_id = req.get("VpcId"); attr = req.get("Attribute")
        return _xml(action, f"<vpcId>{vpc_id}</vpcId><{attr}><value>true</value></{attr}>")

    # --- Subnet ---
    if action == "CreateSubnet":
        sub = backend.create_subnet(req.get("VpcId"), req.get("CidrBlock"))
        tags = req.get_tag_specifications("subnet")
        if tags:
            sub.add_tags(tags)
        return _xml(action, f"<subnet>{sub.to_xml()}</subnet>")

    if action == "ModifySubnetAttribute":
        sid = req.get("SubnetId")
        if sid in backend.subnets:
            val = req.get("MapPublicIpOnLaunch.Value")
            if val: backend.subnets[sid].map_public_ip = val
        return _xml(action, "<return>true</return>")

    if action == "DescribeSubnets":
        sid = req.get_filter("subnet-id"); vid = req.get_filter("vpc-id")
        objs = list(backend.subnets.values())
        if sid: objs = [o for o in objs if o.id == sid]
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return _xml(action, XML.dump_list("subnetSet", objs))

    # --- Security Groups ---
    if action == "CreateSecurityGroup":
        sg = SecurityGroup(req.get("VpcId"), req.get("GroupName"), req.get("GroupDescription"), owner_id=backend.account_id)
        tags = req.get_tag_specifications("security-group")
        if tags:
            sg.add_tags(tags)
        backend.security_groups[sg.id] = sg
        return _xml(action, f"<groupId>{sg.id}</groupId>")

    if action == "AuthorizeSecurityGroupIngress":
        sg = backend.security_groups.get(req.get("GroupId"))
        if sg:
            sg.add_ingress(req.get("IpPermissions.1.IpProtocol"), req.get("IpPermissions.1.FromPort"), req.get("IpPermissions.1.ToPort"), req.get("IpPermissions.1.IpRanges.1.CidrIp"))
        return _xml(action, "<return>true</return>")

    if action == "AuthorizeSecurityGroupEgress":
        sg = backend.security_groups.get(req.get("GroupId"))
        if sg:
            sg.add_egress(req.get("IpPermissions.1.IpProtocol"), req.get("IpPermissions.1.FromPort"), req.get("IpPermissions.1.ToPort"), req.get("IpPermissions.1.IpRanges.1.CidrIp"))
        return _xml(action, "<return>true</return>")

    if action in ("RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress"):
        sg = backend.security_groups.get(req.get("GroupId"))
        if sg:
            rules = sg.ingress if action == "RevokeSecurityGroupIngress" else sg.egress
            rule_id = req.get("SecurityGroupRuleId.1")
            if rule_id:
                rules[:] = [r for r in rules if r["id"] != rule_id]
            else:
                proto = req.get("IpPermissions.1.IpProtocol"); fport = req.get("IpPermissions.1.FromPort")
                tport = req.get("IpPermissions.1.ToPort"); cidr = req.get("IpPermissions.1.IpRanges.1.CidrIp")
                for r in list(rules):
                    if r["p"] == proto and r["f"] == fport and r["t"] == tport and r["c"] == cidr:
                        rules.remove(r); break
        return _xml(action, "<return>true</return>")

    if action == "DescribeSecurityGroups":
        gid = req.get_filter("group-id")
        vid = req.get_filter("vpc-id")
        name = req.get_filter("group-name")

        objs = list(backend.security_groups.values())
        if gid: objs = [o for o in objs if o.id == gid]
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        if name: objs = [o for o in objs if o.name == name]

        return _xml(action, XML.dump_list("securityGroupInfo", objs))

    if action == "DescribeSecurityGroupRules":
        gid = req.get_filter("group-id")
        objs = list(backend.security_groups.values())
        if gid: objs = [o for o in objs if o.id == gid]
        items = "".join([o.rules_xml() for o in objs])
        return _xml(action, f"<securityGroupRuleSet>{items}</securityGroupRuleSet>")

    # --- Network ACLs & Routes ---
    if action == "DescribeNetworkAcls":
        vid = req.get_filter("vpc-id"); objs = list(backend.nacls.values())
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return _xml(action, XML.dump_list("networkAclSet", objs))

    if action == "DescribeRouteTables":
        vid = req.get_filter("vpc-id"); objs = list(backend.route_tables.values())
        if vid: objs = [o for o in objs if o.vpc_id == vid]
        return _xml(action, XML.dump_list("routeTableSet", objs))

    # --- Instances ---
    if action == "RunInstances":
        sgs = req.get_list_prefix("SecurityGroupId.")
        inst = backend.run_instances(req.get("ImageId"), req.get("InstanceType"), req.get("SubnetId"), sgs)
        tags = req.get_tag_specifications("instance")
        if tags:
            inst.add_tags(tags)
        xml = f"""<reservationId>r-{uuid.uuid4().hex[:8]}</reservationId><ownerId>{backend.account_id}</ownerId><instancesSet><item>{inst.to_xml()}</item></instancesSet>"""
        return _xml(action, xml)

    if action == "DescribeInstances":
        iid = req.get_filter("instance-id")
        objs = [backend.instances[iid]] if iid and iid in backend.instances else list(backend.instances.values())
        res_xml = "".join([f"<item><reservationId>r-mock</reservationId><ownerId>{backend.account_id}</ownerId><instancesSet><item>{i.to_xml()}</item></instancesSet></item>" for i in objs])
        return _xml(action, f"<reservationSet>{res_xml}</reservationSet>")

    if action == "DescribeInstanceTypes":
        req_type = req.get_filter("instance-type") or "t2.micro"
        xml = f"""<instanceTypeSet><item><instanceType>{req_type}</instanceType><processorInfo><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><vCpuInfo><defaultVCpus>1</defaultVCpus></vCpuInfo><memoryInfo><sizeInMiB>1024</sizeInMiB></memoryInfo><instanceStorageSupported>false</instanceStorageSupported></item></instanceTypeSet>"""
        return _xml(action, xml)

    if action == "TerminateInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "48"; backend.instances[iid].state_name = "terminated"
        return _xml(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>48</code><name>terminated</name></currentState></item></instancesSet>")

    if action == "StopInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "80"; backend.instances[iid].state_name = "stopped"
        return _xml(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>80</code><name>stopped</name></currentState><previousState><code>16</code><name>running</name></previousState></item></instancesSet>")

    if action == "StartInstances":
        iid = req.get("InstanceId.1")
        if iid in backend.instances:
            backend.instances[iid].state_code = "16"; backend.instances[iid].state_name = "running"
        return _xml(action, f"<instancesSet><item><instanceId>{iid}</instanceId><currentState><code>16</code><name>running</name></currentState><previousState><code>80</code><name>stopped</name></previousState></item></instancesSet>")

    if action == "DescribeInstanceAttribute":
        iid = req.get("InstanceId"); attr = req.get("Attribute")
        val = backend.instances[iid].attrs.get(attr) if iid in backend.instances else None
        # Real AWS omits <value> entirely for an attribute that was never
        # set (e.g. userData on an instance launched without one) rather
        # than inventing a placeholder - inventing one (this used to
        # default everything to the string "true") corrupts attributes
        # like userData, which the provider expects to be valid base64.
        attr_xml = f"<{attr}><value>{val}</value></{attr}>" if val is not None else f"<{attr}/>"
        return _xml(action, f"<instanceId>{iid}</instanceId>{attr_xml}")

    if action == "ModifyInstanceAttribute":
        iid = req.get("InstanceId")
        if iid in backend.instances:
            if req.get("SourceDestCheck.Value"): backend.instances[iid].attrs["sourceDestCheck"] = req.get("SourceDestCheck.Value")
            if req.get("UserData.Value"): backend.instances[iid].attrs["userData"] = req.get("UserData.Value")
        return _xml(action, "<return>true</return>")

    # --- Gateways & EIPs ---
    if action == "AllocateAddress":
        from resources_gateways import ElasticIP
        eip = ElasticIP(backend.pop_eip()); backend.eips[eip.id] = eip
        return _xml(action, f"<allocationId>{eip.id}</allocationId><publicIp>{eip.public_ip}</publicIp><domain>vpc</domain>")

    if action == "DescribeAddresses":
        aid = req.get_filter("allocation-id")
        objs = [backend.eips[aid]] if aid and aid in backend.eips else list(backend.eips.values())
        return _xml(action, XML.dump_list("addressesSet", objs))

    if action == "DescribeAddressesAttribute":
        aid = req.get("AllocationId") or req.get_filter("allocation-id")
        return _xml(action, f"<address><allocationId>{aid}</allocationId><domain>vpc</domain></address>")

    if action == "CreateInternetGateway":
        from resources_gateways import InternetGateway
        igw = InternetGateway(); backend.igws[igw.id] = igw
        return _xml(action, f"<internetGateway>{igw.to_xml()}</internetGateway>")

    if action == "AttachInternetGateway":
        igw = backend.igws.get(req.get("InternetGatewayId"))
        if igw: igw.attachments.append(req.get("VpcId"))
        return _xml(action, "<return>true</return>")

    if action == "DescribeInternetGateways":
        gid = req.get_filter("internet-gateway-id")
        objs = [backend.igws[gid]] if gid and gid in backend.igws else list(backend.igws.values())
        return _xml(action, XML.dump_list("internetGatewaySet", objs))

    if action == "CreateNatGateway":
        from resources_gateways import NatGateway
        subnet_id = req.get("SubnetId"); alloc_id = req.get("AllocationId")
        eip = backend.eips.get(alloc_id)
        nat = NatGateway(subnet_id, alloc_id, backend.subnets[subnet_id].vpc_id, eip.public_ip if eip else "0.0.0.0")
        backend.natgws[nat.id] = nat
        return _xml(action, f"<natGateway>{nat.to_xml()}</natGateway>")

    if action == "DescribeNatGateways":
        nid = req.get_filter("nat-gateway-id")
        objs = [backend.natgws[nid]] if nid and nid in backend.natgws else list(backend.natgws.values())
        return _xml(action, XML.dump_list("natGatewaySet", objs))

    if action == "DeleteNatGateway":
        nid = req.get("NatGatewayId")
        if nid in backend.natgws: backend.natgws[nid].state = "deleted"
        return _xml(action, f"<natGatewayId>{nid}</natGatewayId>")

    # --- Deletions ---
    # Unlike NAT gateways (which linger with state=deleted - see above,
    # matches real AWS), a deleted VPC/subnet/security group/internet
    # gateway/EIP simply stops appearing in Describe* at all in real AWS.
    # Terraform's delete-waiters for these poll until the resource is gone,
    # not until some terminal state appears - so these need to actually be
    # removed from the backend, or a `terraform destroy` hangs forever
    # retrying a resource that (from its point of view) never finishes
    # deleting.
    if action == "DeleteVpc":
        backend.vpcs.pop(req.get("VpcId"), None)
        return _xml(action, "<return>true</return>")

    if action == "DeleteSubnet":
        backend.subnets.pop(req.get("SubnetId"), None)
        return _xml(action, "<return>true</return>")

    if action == "DeleteSecurityGroup":
        backend.security_groups.pop(req.get("GroupId"), None)
        return _xml(action, "<return>true</return>")

    if action == "DetachInternetGateway":
        igw = backend.igws.get(req.get("InternetGatewayId"))
        if igw:
            vpc_id = req.get("VpcId")
            igw.attachments = [v for v in igw.attachments if v != vpc_id]
        return _xml(action, "<return>true</return>")

    if action == "DeleteInternetGateway":
        backend.igws.pop(req.get("InternetGatewayId"), None)
        return _xml(action, "<return>true</return>")

    if action == "ReleaseAddress":
        aid = req.get("AllocationId")
        backend.eips.pop(aid, None)
        return _xml(action, "<return>true</return>")

    # --- Tags ---
    if action == "CreateTags":
        rid = req.get("ResourceId.1")
        res = backend.find_any(rid)
        if res: res.add_tags({req.get("Tag.1.Key"): req.get("Tag.1.Value")})
        return _xml(action, "<return>true</return>")

    if action == "DescribeTags":
        rid = req.get_filter("resource-id"); items = ""
        if rid:
            res = backend.find_any(rid)
            if res: items = "".join([f"<item><resourceId>{rid}</resourceId><resourceType>res</resourceType><key>{k}</key><value>{v}</value></item>" for k, v in res.tags.items()])
        return _xml(action, f"<tagSet>{items}</tagSet>")

    # --- Common Success Stubs ---
    if action in ["CreateRoute", "DeleteRoute", "AssociateRouteTable", "ModifyNetworkInterfaceAttribute", "DescribeLaunchTemplates", "DescribeNetworkInterfaces"]:
        return _xml(action, "<return>true</return>")

    return None
