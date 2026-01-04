from flask import Flask, request, Response
import uuid
import re

app = Flask(__name__)

# --- Relational State Store ---
# This dictionary acts as your in-memory database.
state = {
    "vpcs": {}, 
    "subnets": {}, 
    "route_tables": {}, 
    "security_groups": {}, 
    "network_acls": {},
    "account_id": "123456789012",
}

def get_filter(form_data, filter_name):
    """
    Retrieves a value for a specific filter name.
    Handles both generic filters (Filter.x.Name=vpc-id) and direct params (VpcId.1).
    """
    # 1. Check Generic Filters (e.g., Filter.1.Name=group-name -> Filter.1.Value.1=default)
    for key, val in form_data.items():
        if val == filter_name: 
            # Found the filter name, grab the corresponding value
            prefix = key.rsplit('.', 1)[0] 
            return form_data.get(f"{prefix}.Value.1")
            
    # 2. Check Direct Parameters (Legacy/Specific)
    if filter_name == 'group-id': return form_data.get("GroupId.1")
    if filter_name == 'vpc-id': return form_data.get("VpcId.1")
    if filter_name == 'group-name': return form_data.get("GroupName.1")
    if filter_name == 'subnet-id': return form_data.get("SubnetId.1")
    return None

def xml_wrapper(action, content):
    return f'<{action}Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>{uuid.uuid4()}</requestId>{content}</{action}Response>'

@app.route("/", methods=["POST"])
def gateway():
    action = request.form.get("Action")
    print(f"--- Action: {action} ---")

    # ==========================================
    # 1. IDENTITY & ATTRIBUTES
    # ==========================================
    if action == "GetCallerIdentity":
        content = f"<GetCallerIdentityResult><Arn>arn:aws:iam::{state['account_id']}:user/emulator</Arn><UserId>AIDACKCEVSQ6C2EXAMPLE</UserId><Account>{state['account_id']}</Account></GetCallerIdentityResult>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')
    
    elif action == "GetUser":
        content = f"<GetUserResult><User><UserName>emulator</UserName><Arn>arn:aws:iam::{state['account_id']}:user/emulator</Arn></User></GetUserResult>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    elif action == "DescribeVpcAttribute":
        # Reflects the requested attribute back as 'true' to satisfy Terraform checks
        vpc_id, attr = request.form.get("VpcId"), request.form.get("Attribute")
        content = f"<vpcId>{vpc_id}</vpcId><{attr}><value>true</value></{attr}>"
        return Response(xml_wrapper(action, content), mimetype='text/xml')

    # ==========================================
    # 2. DESTRUCTION SAFETY (ENIs)
    # ==========================================
    elif action == "DescribeNetworkInterfaces":
        # Return empty list so Terraform thinks it's safe to delete Security Groups/Subnets
        return Response(xml_wrapper(action, "<networkInterfaceSet/>"), mimetype='text/xml')

    # ==========================================
    # 3. SECURITY GROUPS & RULES
    # ==========================================
    elif action == "DescribeSecurityGroups":
        target_id = get_filter(request.form, 'group-id')
        target_vpc = get_filter(request.form, 'vpc-id')
        target_name = get_filter(request.form, 'group-name')

        items = ""
        for sg_id, d in state["security_groups"].items():
            # Apply Filters
            if target_id and sg_id != target_id: continue
            if target_vpc and d['vpc_id'] != target_vpc: continue
            if target_name and d['name'] != target_name: continue

            # Build Legacy Ingress XML (for older Terraform checks)
            ingress = "".join([f"<item><ipProtocol>{r['proto']}</ipProtocol><fromPort>{r['from']}</fromPort><toPort>{r['to']}</toPort><ipRanges><item><cidrIp>{r['cidr']}</cidrIp></item></ipRanges></item>" for r in d.get('ingress', [])])
            
            items += f"""<item>
                <ownerId>{state['account_id']}</ownerId>
                <groupId>{sg_id}</groupId>
                <groupName>{d['name']}</groupName>
                <groupDescription>{d.get('desc', 'Managed by Terraform')}</groupDescription>
                <vpcId>{d['vpc_id']}</vpcId>
                <ipPermissions>{ingress}</ipPermissions>
                <ipPermissionsEgress/>
            </item>"""
        return Response(xml_wrapper(action, f"<securityGroupInfo>{items}</securityGroupInfo>"), mimetype='text/xml')

    elif action == "DescribeSecurityGroupRules":
        # Modern Terraform calls this to verify specific rules by ID
        target_group = get_filter(request.form, 'group-id')
        rules_xml = ""
        for sg_id, data in state["security_groups"].items():
            if target_group and sg_id != target_group: continue
            for rule in data.get("ingress", []):
                rules_xml += f"""<item>
                    <securityGroupRuleId>{rule['id']}</securityGroupRuleId>
                    <groupId>{sg_id}</groupId>
                    <ownerId>{state['account_id']}</ownerId>
                    <isEgress>false</isEgress>
                    <ipProtocol>{rule['proto']}</ipProtocol>
                    <fromPort>{rule['from']}</fromPort>
                    <toPort>{rule['to']}</toPort>
                    <cidrIpv4>{rule['cidr']}</cidrIpv4>
                </item>"""
        return Response(xml_wrapper(action, f"<securityGroupRuleSet>{rules_xml}</securityGroupRuleSet>"), mimetype='text/xml')

    # ==========================================
    # 4. RESOURCE DISCOVERY (VPC, Subnet, NACL, Route)
    # ==========================================
    elif action == "DescribeVpcs":
        items = ""
        for v_id, d in state["vpcs"].items():
            items += f"""<item>
                <vpcId>{v_id}</vpcId>
                <state>available</state>
                <cidrBlock>{d['cidr']}</cidrBlock>
                <isDefault>false</isDefault>
                <instanceTenancy>default</instanceTenancy>
            </item>"""
        return Response(xml_wrapper(action, f"<vpcSet>{items}</vpcSet>"), mimetype='text/xml')

    elif action == "DescribeSubnets":
        items = ""
        for s_id, d in state["subnets"].items():
            items += f"""<item>
                <subnetId>{s_id}</subnetId>
                <vpcId>{d['vpc_id']}</vpcId>
                <cidrBlock>{d['cidr']}</cidrBlock>
                <availabilityZone>us-east-1a</availabilityZone> 
                <availableIpAddressCount>251</availableIpAddressCount>
                <state>available</state>
                <mapPublicIpOnLaunch>false</mapPublicIpOnLaunch>
            </item>"""
        return Response(xml_wrapper(action, f"<subnetSet>{items}</subnetSet>"), mimetype='text/xml')

    elif action == "DescribeNetworkAcls":
        # Terraform filters NACLs by VPC ID to find the default one
        target_vpc = get_filter(request.form, 'vpc-id')
        items = ""
        for acl_id, d in state["network_acls"].items():
            if target_vpc and d['vpc_id'] != target_vpc: continue
            items += f"<item><networkAclId>{acl_id}</networkAclId><vpcId>{d['vpc_id']}</vpcId><default>true</default><entrySet><item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item></entrySet></item>"
        return Response(xml_wrapper(action, f"<networkAclSet>{items}</networkAclSet>"), mimetype='text/xml')

    elif action == "DescribeRouteTables":
        target_vpc = get_filter(request.form, 'vpc-id')
        items = ""
        for rtb_id, d in state["route_tables"].items():
            if target_vpc and d['vpc_id'] != target_vpc: continue
            items += f"<item><routeTableId>{rtb_id}</routeTableId><vpcId>{d['vpc_id']}</vpcId><associationSet><item><main>true</main></item></associationSet></item>"
        return Response(xml_wrapper(action, f"<routeTableSet>{items}</routeTableSet>"), mimetype='text/xml')

    # ==========================================
    # 5. CREATION LOGIC
    # ==========================================
    elif action == "CreateVpc":
        vpc_id = f"vpc-{uuid.uuid4().hex[:8]}"
        state["vpcs"][vpc_id] = {"cidr": request.form.get("CidrBlock")}
        
        # Auto-create Shadow Resources (Required for Terraform verification)
        state["network_acls"][f"acl-{uuid.uuid4().hex[:8]}"] = {"vpc_id": vpc_id}
        state["route_tables"][f"rtb-{uuid.uuid4().hex[:8]}"] = {"vpc_id": vpc_id}
        state["security_groups"][f"sg-{uuid.uuid4().hex[:8]}"] = {"vpc_id": vpc_id, "name": "default", "desc": "default VPC security group", "ingress": []}
        
        return Response(xml_wrapper(action, f"<vpc><vpcId>{vpc_id}</vpcId><state>available</state><cidrBlock>{state['vpcs'][vpc_id]['cidr']}</cidrBlock></vpc>"), mimetype='text/xml')

    elif action == "CreateSecurityGroup":
        sg_id = f"sg-{uuid.uuid4().hex[:8]}"
        state["security_groups"][sg_id] = {
            "vpc_id": request.form.get("VpcId"),
            "name": request.form.get("GroupName"),
            "desc": request.form.get("GroupDescription", "Managed by Terraform"),
            "ingress": []
        }
        return Response(xml_wrapper(action, f"<groupId>{sg_id}</groupId>"), mimetype='text/xml')

    elif action == "CreateSubnet":
        s_id = f"subnet-{uuid.uuid4().hex[:8]}"
        state["subnets"][s_id] = {"vpc_id": request.form.get("VpcId"), "cidr": request.form.get("CidrBlock")}
        return Response(xml_wrapper(action, f"<subnet><subnetId>{s_id}</subnetId><state>available</state></subnet>"), mimetype='text/xml')

    # ==========================================
    # 6. RULE & UPDATE LOGIC
    # ==========================================
    elif action == "AuthorizeSecurityGroupIngress":
        sg_id = request.form.get("GroupId")
        if sg_id in state["security_groups"]:
            # Generate stable ID so DescribeSecurityGroupRules works
            rule_id = f"sgr-{uuid.uuid4().hex[:8]}"
            rule = {
                "id": rule_id,
                "proto": request.form.get("IpPermissions.1.IpProtocol", "-1"),
                "from": request.form.get("IpPermissions.1.FromPort", "0"),
                "to": request.form.get("IpPermissions.1.ToPort", "65535"),
                "cidr": request.form.get("IpPermissions.1.IpRanges.1.CidrIp", "0.0.0.0/0")
            }
            state["security_groups"][sg_id]["ingress"].append(rule)
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "RevokeSecurityGroupIngress":
        # Supports modern Terraform rule deletion by ID
        rule_id = request.form.get("SecurityGroupRuleIds.1")
        if rule_id:
            for sg in state["security_groups"].values():
                sg["ingress"] = [r for r in sg["ingress"] if r["id"] != rule_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    # ==========================================
    # 7. DELETION LOGIC
    # ==========================================
    elif action == "DeleteSecurityGroup":
        target_id = request.form.get("GroupId")
        if target_id in state["security_groups"]:
            del state["security_groups"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DeleteSubnet":
        target_id = request.form.get("SubnetId")
        if target_id in state["subnets"]:
            del state["subnets"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    elif action == "DeleteVpc":
        target_id = request.form.get("VpcId")
        if target_id in state["vpcs"]:
            del state["vpcs"][target_id]
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    # ==========================================
    # 8. CATCH-ALL (Prevents 400 Errors on minor actions)
    # ==========================================
    elif action in ["RevokeSecurityGroupEgress", "AuthorizeSecurityGroupEgress", "AssociateRouteTable"]:
        return Response(xml_wrapper(action, "<return>true</return>"), mimetype='text/xml')

    return Response(xml_wrapper(action, f"<Error><Code>InvalidAction</Code><Message>{action} not implemented</Message></Error>"), status=400, mimetype='text/xml')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4566)