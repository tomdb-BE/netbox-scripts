from ipam.models import IPAddress
from ipam.choices import IPAddressRoleChoices, IPAddressStatusChoices
from extras.scripts import (    
    BooleanVar,
    ChoiceVar,
    IntegerVar,
    IPAddressVar,
    MultiChoiceVar,
    Script,
    StringVar,
    )
from ipaddress import ip_address
import powerdns

class NetboxPDNSAPIClient:
    def __init__(self, logger, url, key):                
        self.endpoint = None
        self.log = logger
        self.ready = False
        if url and key:                                
            try:
                client = powerdns.PDNSApiClient(
                    api_endpoint=url, api_key=key
                )
            except:
                self.log["failure"]("Connecting to PowerDNS API")
        else:
            self.log["failure"]("Invalid PowerDNS API url or key")            
        if client:
            try:
                self.endpoint = powerdns.PDNSEndpoint(client).servers[0]
            except:
                self.log["failure"]("Setting up PowerDNS endpoint")
        if self.endpoint:
            self.ready = True
            self.log["success"]("PowerDNS endpoint ready")       


class NetboxPDNSZone:
    def __init__(self, logger, api_endpoint, name,
                reverse=False, comment="", force=False):
        self.api_endpoint = api_endpoint
        self.comment = comment
        self.force = force
        self.log = logger
        self.name = ""
        self.record_type = "A"
        self.ready = False
        self.reverse = reverse            
        self.rr_sets_to_update = []
        self.rr_sets_to_delete = []
        self.to_delete = []
        self.to_update = []
        self.zone = None
        
        self.log["info"](f"Setting up zone {name}")
        if name and self.api_endpoint:
            if self.reverse:
                self.record_type = "PTR"
            self.set_zone(name)
        else:
            self.log["failure"]("Failed to setup zone")


    def set_zone(self, name):
        zone = None
        name = name if name.endswith('.') else f"{name}."
        try:
            zone = self.api_endpoint.get_zone(name)
        except:
            zone = None
        if zone:
            self.zone = zone
            self.name = name[:-1]
            self.ready = True
            self.log["success"](f"Zone {self.name} is ready")
        else:
            self.ready = False
            self.log["failure"](f"Cannot find PDNS zone {name}") 


    def is_netbox_managed(self, record):
        for comment in record["comments"]:                    
            if comment["content"] == self.comment:
                return True
        return False           


    def record_contains(self, record, content):
        for content_record in record["records"]:
            if isinstance(content_record, dict):   
                if content_record["content"] == content:
                    return True
            elif content_record == content:
                return True
        return False


    def check_record(self, name, content, delete=False,
                        create=False, sync=False):
        summary = f"{self.record_type} {name} {content}"
        matching_records = self.zone.get_record(name)
        if matching_records:
            if create:
                self.log["warning"](f"Record already exists: {summary}")
                return False
            for record in matching_records:                
                if record["type"] != self.record_type:
                    continue
                if not self.is_netbox_managed(record):
                    self.log["warning"](
                        f"Record not managed by Netbox: {summary}")
                    return self.force                        
                if not delete and self.record_contains(record, content):
                    if not sync and not self.force:                
                        self.log["warning"](
                            f"Record already exists: {summary}")  
                        return False
        elif delete:
            self.log["warning"](
                f"Trying to delete a record that doesn't exist {summary}")            
            return False
        return True


    def create_rr_set(self, name, content="", comments=""):
        rr_set = powerdns.RRSet(
            name=name,
            rtype=self.record_type,
            records=[],
            comments=[]                    
        )
        if content:
            rr_set["records"].append(
                {
                    "content": content,
                    "disabled": False
                }
            )
            if comments:
                rr_set["comments"].append(
                    powerdns.Comment(comments)
                )            
        return rr_set


    def add_to_delete_list(self, name):
        if name in self.to_delete:
            self.log["warning"](
                f"Duplicate record to delete: {self.record_type} {name}")
            return
        self.to_delete.append(name)            
        rr_set = self.create_rr_set(name)
        self.rr_sets_to_delete.append(rr_set)
        self.log["debug"](
            f"Added to delete list: {self.record_type} {name}")      


    def add_to_update_list(self, name, content, comment):
        if name in self.to_update:
            self.log["warning"](
                f"Duplicate record to update: {self.record_type} {name}")
            return
        self.to_update.append(name)
        rr_set = self.create_rr_set(name, content, comment)                                                  
        self.rr_sets_to_update.append(rr_set)
        self
        self.log["debug"](
            f"Added to update list: {self.record_type} {name} {content}")                  


    def update_pdns_records(self, delete=False):
        if delete:         
            count = len(self.rr_sets_to_delete)
            action = "Delete"
        else:
            count = len(self.rr_sets_to_update)
            action = "Update"
        if self.ready and count > 0:                        
            try:
                if delete:
                    self.zone.delete_records(self.rr_sets_to_delete)
                else:
                    self.zone.create_records(self.rr_sets_to_update)
            except:
                self.log["failure"](f"{action} {count} records in {self.name}")
                return False
            self.log["success"](
                f"{action}d {count} records in {self.name}")
        return True


    def clean_zone(self, content):
        self.log["debug"](f"Cleaning {self.name} for content {content}")            
        for record in self.zone.records:                
            if record["type"] != self.record_type:                    
                continue
            if not self.is_netbox_managed(record):
                continue                
            if self.record_contains(record, content):                                             
                self.add_to_delete_list(record["name"])            


    def purge_zone(self):
        self.log["warning"](f"Purging zone {self.name}")            
        for record in self.zone.records: 
            if record["type"] != self.record_type:                    
                continue
            if self.force or self.is_netbox_managed(record):
                self.add_to_delete_list(record["name"])
        return True


    def set_record(self, name, content,create=False,
                            delete=False, sync=False, comment=""):
        if not self.ready:
            return False            
        if not comment:
            comment = self.comment
        if self.reverse:
            content = content if content.endswith('.') else f"{content}."
        name = name if name.endswith('.') else f"{name}."
        if not self.check_record(name, content, delete, create, sync):            
            return sync
        if delete:
            self.add_to_delete_list(name)
        else:
            self.add_to_update_list(name, content, comment)            
            self.clean_zone(content)           
        return True


    def add_record(self, name, content):
        self.set_record(name, content, create=True)


    def del_record(self, name, content):
        self.set_record(name, content, delete=True)


    def commit(self):
        self.log["info"](f"Committing changes to zone {self.name}")
        if self.update_pdns_records(delete=False):
            if self.update_pdns_records(delete=True):
                return True                    
        return False
        

class NetboxPDNSSync(Script):

    PDNS_ACTIONS = (
        ('add', 'Create record'),            
        ('set', 'Update record'),
        ('del', 'Delete record'),
        ('sync_zones', 'Sync zones'),        
        ('purge_zones', 'Purge zones'),
    )     

    class Meta:
        name = "Netbox PowerDNS sync script"
        description = "Synchronize PowerDNS with Netbox data"

    pdns_action = ChoiceVar(
        default = "set",
        description = "Action",
        label = "Action",
        required = False,
        choices = PDNS_ACTIONS       
    )

    pdns_api_url = StringVar(
        default = "",
        description = "PowerDNS API URL",
        label = "API URL",
        required = False
    )

    pdns_api_key = StringVar(  
        default = "",  
        description = "PowerDNS API Key",
        label = "API Key",
        required = False
    )

    pdns_forward_zones = StringVar(
        default = "",
        description = "Comma seperated list of forward zones to update",
        label = "Forward zones",
        required = False
    )

    pdns_reverse_zones = StringVar(
        default = "",
        description = "Comma seperated list of reverse zones to update",
        label = "Reverse zones",
        required = False
    )

    dns_name = StringVar(
        default = "",
        label = "DNS Name",
        description = "DNS A record to create or update",
        required = False
    )
    
    address = IPAddressVar(
        default = "",
        label = "IP",
        description = "IPv4 Address of the record",
        required = False
    )  

    pdns_managed_comment = StringVar(
        default = "Netbox managed",
        description = "Comment indicating record is Netbox managed",
        label = "Comment",
        required = False
    )  

    pdns_filter_include_status = MultiChoiceVar(
        default = [],
        description = "IP status to include",
        label = "Include Status",
        required = False,
        choices = IPAddressStatusChoices       
    ) 

    pdns_filter_exclude_status = MultiChoiceVar(
        default = [],
        description = "IP status to exclude",
        label = "Exclude Status",
        required = False,
        choices = IPAddressStatusChoices       
    )   

    pdns_filter_include_role = MultiChoiceVar(
        default = [],
        description = "IP roles to include",
        label = "Include Roles",
        required = False,
        choices = IPAddressRoleChoices       
    ) 
    
    pdns_filter_exclude_role = MultiChoiceVar(
        default = [],
        description = "IP roles to exclude",
        label = "Exclude Roles",
        required = False,
        choices = IPAddressRoleChoices       
    )   

    pdns_reverse = BooleanVar(
        default = True,
        description = "Create/update the corresponding PTR record",
        label = "PTR",
        required = False
    )

    pdns_dry_run = BooleanVar(
        default = False,
        description = "Test only, no commits",
        label = "Dry run",
        required = False
    )

    pdns_force = BooleanVar(
        default = False,
        description = "Ignores netbox managed comment and overwrites existing records",
        label = "Force",
        required = False
    )    

    params = None

    class NetboxPDNSParameters:
        def __init__(self, logger, data):            
            self.action = "set"            
            self.api = None
            self.blocked_zones = []
            self.dataset = {}
            self.filters = {}            
            self.ip_address = ""
            self.ip_dns_name = ""
            self.log = logger            
            self._valid = False            

            self.settings = {
                "action": "",
                "api_key": "",
                "api_url": "",                                
                "dry_run": False,
                "enable_reverse": True,                
                "force": False,
                "forward_zones": "",
                "managed_comment": "Netbox managed",
                "reverse_zones": ""
            }
            for key in self.settings:
                settings_key = "pdns_" + key
                if settings_key in data and data[settings_key]:
                    self.settings[key] = data[settings_key]
            if self.settings["action"]:
                self.action = self.settings["action"]
            if self.settings["forward_zones"]:
                self.settings["forward_zones"] = [z.strip() for z in \
                    self.settings["forward_zones"].split(",")]
            if self.settings["reverse_zones"]:                    
                self.settings["reverse_zones"] = [z.strip() for z in \
                    self.settings["reverse_zones"].split(",")]

            if "address" in data and data["address"]:
                self.ip_address = str(data["address"])
            if "dns_name" in data and data["dns_name"]:                
                self.ip_dns_name = str(data["dns_name"]).lower().strip()

            self.api = NetboxPDNSAPIClient(
                logger=self.log,
                url=self.settings["api_url"],
                key=self.settings["api_key"]
            )            
            if not self.api and self.api.ready:
                return

            self.get_filters(data)                    

            if self.action in ["add", "del", "set"]:
                self.action = self.action + "_record"
                if not self.ip_dns_name:
                    self.log["failure"]("Missing DNS name")
                    return                
                if self.action != "del_record" and not self.ip_address:
                    self.log["failure"]("Missing IP address")
                    return                
                self.get_records(self.ip_dns_name, self.ip_address)
            elif self.action in ["sync_zones", "purge_zones"]:                
                if self.settings["forward_zones"]:
                    self.get_records()                
                elif self.settings["reverse_zones"]:
                    self.get_records(zones_reverse=True)        
                else:
                    self.log["failure"]("Missing zone name(s)")
                    return                
            else:
                self.log["failure"](f"Invalid action {self.action}")
                return

            if self.filters:
                self.log["debug"](f"Active filters: {self.filters}")                            

            if not self.dataset:                
                self.log["warning"]("No matching records to perform action")
                return

            self.log["debug"](f"Records to update: {self.dataset}")

            self.log["info"](f"Starting action: {self.action}")

            if self.settings["force"]:
                self.log["warning"]("FORCE enabled!")

            self._valid = True


        @property
        def is_valid(self):
            return self._valid


        def add_filter(self, filters, action, attr, values):
            if (not attr or not values):
                return filters
            if not isinstance(values, list):
                values = values.split(",")
            filters[action][f"{attr}__in"] = values            
            return filters


        def get_filters(self, data):
            for action in ["include", "exclude"]:
                self.filters[action] = {}
                filter_key = f"pdns_filter_{action}"
                if (filter_key in data and 
                isinstance(data[filter_key], dict)):
                    for attr, values in data[filter_key].items():
                        self.add_filter(self.filters,                            
                            action=action, 
                            attr=attr, 
                            values=values)
                for attr in ["role", "status"]:                    
                    filter_key = f"{filter_key}_{attr}"
                    if filter_key in data and data[filter_key]:
                        self.add_filter(self.filters,                                 
                            action=action, 
                            attr=attr, 
                            values=data[filter_key])


        def get_reverse_zone_name(self, ptr):
            attempts = 0
            name = ptr
            zone = None               
            while not zone:
                attempts += 1
                octet, _, name = name.partition(".")
                if name in self.dataset:
                    return name
                if name in self.blocked_zones:
                    return ""               
                if not octet.isnumeric() or not name or attempts > 3:
                    self.log_failure(f"Cannot find reverse zone {name}")
                    return ""
                zone = self.api.endpoint.get_zone(f"{name}.")
            if (self.settings["reverse_zones"] and 
                name not in self.settings["reverse_zones"]):
                self.blocked_zones.append(name)
                return ""
            return name


        def get_zone(self, dns_name="", ptr=""):
            is_reverse = False
            search_name = ""            
            if dns_name:                
                host, _, search_name = dns_name.partition('.')
                if not search_name or (self.settings["forward_zones"]
                    and search_name not in self.settings["forward_zones"]):
                    self.log["Warning"](
                        f"Unable to set {dns_name}-Invalid zone {search_name}")
                    return None
            elif ptr:
                is_reverse = True
                search_name = self.get_reverse_zone_name(ptr)
                if not search_name:
                    self.log["Warning"](
                        f"Unable to set {ptr}-Invalid zone {search_name}")
                    return None

            if search_name in self.dataset:
                return search_name

            zone = NetboxPDNSZone(
                        logger=self.log,
                        api_endpoint=self.api.endpoint, 
                        name=f"{search_name}",
                        reverse=is_reverse,
                        comment=self.settings["managed_comment"],
                        force=self.settings["force"]
                        )
            if zone.ready:
                self.dataset[search_name] = {"zone": zone, "records": []}                
                return search_name
            
            return ""


        def get_records(self, dns_name="", ip="", zones_reverse=False):
            exclusions = self.filters["exclude"]            
            filters = self.filters["include"]            
            obj_ips = []            

            if dns_name:
                filters["dns_name"] = dns_name
                if ip:
                    filters["address"] = ip
                obj_ips = IPAddress.objects.filter(**filters).exclude(
                                                        **exclusions)
            elif zones_reverse:
                for zone in self.settings["reverse_zones"]:
                    ip_part = zone.replace(".in-addr.arpa", "")
                    ip_part = ".".join(list(reversed(ip_part.split('.'))))
                    filters["address__startswith"] = ip_part
                    obj_ips += IPAddress.objects.filter(**filters).exclude(
                                                            **exclusions)
            else:            
                for zone in self.settings["forward_zones"]:
                    filters["dns_name__endswith"] = zone
                    obj_ips += IPAddress.objects.filter(**filters).exclude(
                                                            **exclusions)                

            for obj_ip in obj_ips:                
                if not obj_ip.dns_name:
                    continue
                ip = str(obj_ip.address.ip)
                fqdn = str(obj_ip.dns_name)

                if not zones_reverse:
                    zone_name = self.get_zone(dns_name=fqdn)
                    if zone_name:
                        record = {
                            "name": fqdn,
                            "content": ip
                        }
                        self.dataset[zone_name]["records"].append(record)

                if not self.settings["enable_reverse"]:
                    continue

                ptr = f"{'.'.join(
                    list(reversed(ip.split('.'))))}.in-addr.arpa"
                zone_name = self.get_zone(ptr=ptr)
                if zone_name:
                    record = {
                        "name": ptr,
                        "content": f"{fqdn}."
                    }
                    self.dataset[zone_name]["records"].append(record)            

   
    def get_logger(self):
        return {
            "success" : self.log_success,
            "debug"   : self.log_debug,
            "info"    : self.log_info,
            "warning" : self.log_warning,
            "failure" : self.log_failure,            
        }
  

    def set_zone_records(self, zone, create=False, delete=False, sync=False):          
        if not zone["zone"] or not zone["records"]:
            return False
        for record in zone["records"]:
            if not zone["zone"].set_record(
                                name=record["name"],
                                content=record["content"],
                                create=create,
                                delete=delete,
                                sync=sync
                                ):
                return False
        if (self.params.settings["dry_run"] or
            zone["zone"].commit()):
            return True
        return False        


    def run(self, data, commit):
        logger = self.get_logger()
        self.params = self.NetboxPDNSParameters(logger, data)

        if not self.params or not self.params.is_valid:
            return("FAILURE")

        create = False
        delete = False
        sync = False

        if self.params.action == "add_record":
            create = True
        if self.params.action in ["del_record", "purge_zones"]:
            delete = True
        if self.params.action in ["purge_zones", "sync_zones"]:
            sync = True

        for zone in self.params.dataset.values():            
            if not self.set_zone_records(zone, create, delete, sync):
                return("FAILURE")   

        return("SUCCESS")
        