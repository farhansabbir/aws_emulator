import uuid
import datetime

class XML:
    """Helper to generate XML strings."""
    @staticmethod
    def wrap(action, content):
        req_id = str(uuid.uuid4())
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <{action}Response xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
            {content}
            <requestId>{req_id}</requestId>
        </{action}Response>"""

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