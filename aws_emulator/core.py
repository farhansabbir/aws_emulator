import uuid
import datetime

class XML:
    """Helper to generate XML strings."""
    @staticmethod
    def wrap(action, content, namespace="http://ec2.amazonaws.com/doc/2016-11-15/"):
        """EC2-protocol envelope: result elements flattened directly under
        <ActionResponse>, with a bare <requestId> sibling."""
        req_id = str(uuid.uuid4())
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <{action}Response xmlns="{namespace}">
            {content}
            <requestId>{req_id}</requestId>
        </{action}Response>"""

    @staticmethod
    def wrap_query(action, result_content, namespace="https://iam.amazonaws.com/doc/2010-05-08/"):
        """AWS "query" protocol envelope used by IAM/STS: results nested in
        <ActionResult>, with the request id under <ResponseMetadata>."""
        req_id = str(uuid.uuid4())
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <{action}Response xmlns="{namespace}">
            <{action}Result>
                {result_content}
            </{action}Result>
            <ResponseMetadata>
                <RequestId>{req_id}</RequestId>
            </ResponseMetadata>
        </{action}Response>"""

    @staticmethod
    def error_query(code, message, status=400, error_type="Sender", namespace="https://iam.amazonaws.com/doc/2010-05-08/"):
        req_id = str(uuid.uuid4())
        body = f"""<?xml version="1.0" encoding="UTF-8"?>
        <ErrorResponse xmlns="{namespace}">
            <Error>
                <Type>{error_type}</Type>
                <Code>{code}</Code>
                <Message>{message}</Message>
            </Error>
            <RequestId>{req_id}</RequestId>
        </ErrorResponse>"""
        return body, status

    @staticmethod
    def dump_list(wrapper_name, item_list):
        items = "".join([f"<item>{x.to_xml()}</item>" for x in item_list])
        return f"<{wrapper_name}>{items}</{wrapper_name}>"

class RequestHelper:
    """Parses AWS-style flattened parameters."""
    def __init__(self, form_data):
        self.data = form_data

    def get(self, name, default=None):
        return self.data.get(name, default)

    def get_list_prefix(self, prefix):
        items = []
        for k, v in self.data.items():
            if k.startswith(prefix) and "." in k:
                items.append(v)
        return items

    def get_tag_specifications(self, resource_type):
        """Parses TagSpecification.N.ResourceType/Tag.M.Key/Value params
        (how RunInstances etc. carry tags-at-creation-time) into a dict,
        for every N whose ResourceType matches."""
        tags = {}
        n = 1
        while f"TagSpecification.{n}.ResourceType" in self.data:
            if self.data[f"TagSpecification.{n}.ResourceType"] == resource_type:
                m = 1
                while f"TagSpecification.{n}.Tag.{m}.Key" in self.data:
                    key = self.data[f"TagSpecification.{n}.Tag.{m}.Key"]
                    value = self.data.get(f"TagSpecification.{n}.Tag.{m}.Value", "")
                    tags[key] = value
                    m += 1
            n += 1
        return tags

    def get_filter(self, name):
        # 1. Search Generic Filters (Filter.x.Name)
        for k, v in self.data.items():
            if v == name and k.startswith("Filter.") and k.endswith(".Name"):
                idx = k.split('.')[1] 
                return self.data.get(f"Filter.{idx}.Value.1")
        
        # 2. Direct Parameter Map
        direct_map = {
            'vpc-id': 'VpcId.1', 'subnet-id': 'SubnetId.1', 
            'group-id': 'GroupId.1', 'instance-id': 'InstanceId.1',
            'allocation-id': 'AllocationId.1', 'network-interface-id': 'NetworkInterfaceId.1',
            'internet-gateway-id': 'InternetGatewayId.1', 'nat-gateway-id': 'NatGatewayId.1',
            'instance-type': 'InstanceType.1'
        }
        return self.data.get(direct_map.get(name))

class AWSResource:
    """Base class for all simulated resources."""
    def __init__(self, resource_type):
        self.id = f"{resource_type}-{uuid.uuid4().hex[:8]}"
        self.tags = {}
        self.created_at = datetime.datetime.utcnow().isoformat() + "Z"

    def to_xml(self): 
        raise NotImplementedError

    def add_tags(self, tag_dict): 
        self.tags.update(tag_dict)

    def render_tags(self):
        if not self.tags: return ""
        items = "".join([f"<item><key>{k}</key><value>{v}</value></item>" for k, v in self.tags.items()])
        return f"<tagSet>{items}</tagSet>"