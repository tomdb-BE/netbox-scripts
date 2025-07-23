import json, requests
from ipam.models import IPAddress, Prefix, Role
from dcim.models import Interface
from virtualization.models import VMInterface
from ipam.choices import PrefixStatusChoices
from extras.scripts import (    
    BooleanVar,
    ChoiceVar,
    IntegerVar,
    IPAddressVar,
    MultiChoiceVar,
    MultiObjectVar,
    Script,
    StringVar,
    )

class NetboxOpnSenseAPIClient:
    
    def __init__(self, settings):        
        self.auth = ()
        self.base_url = settings["base_url"]
        self.controller = settings["controller"]
        self.error = {"error": ""}
        self.log = settings["logger"]
        self.module = settings["module"]
        self.ready = False
        self.verify = settings["verify_ssl"]
        if not self.base_url:
            self.failure("Missing API base url")
            return
        if not settings["key"]:
            self.failure("Missing API key")
            return
        if not settings["secret"]:
            self.failure("Missing API secret")
            return        
        self.auth = (settings["key"], settings["secret"])
        self.ready = True
        version = ""
        if settings["test"]:
            version = self.test()
            if not version:
                return
        self.log["success"](f"OpnSense API{version} ready!")


    def check_response(self, req):            
        if not req.status_code:
            return self.failure(f"Request to API failed") 
        if req.status_code != 200:
            return self.failure(
                f"Request to API failed with code {req.status_code}")
        response = json.loads(req.text)
        if response and "result" in response:
            if response["result"] == "failed":
                if "validations" in response:
                    response = response["validations"]
                return self.failure(
                    f"API action failed: {response}")
        return response


    def check_url(self, command, module, controller, parameters=""):
        controller = self.controller if not controller else controller
        module = self.module if not module else module
        if not self.ready:
            return "ERROR: API not initialized"
        if not command:
            return "ERROR: Missing command"
        if not controller:
            return "ERROR: Missing controller"
        if not module:
            return "ERROR: Missing module"
        url = f"{self.base_url}/api/{module}/{controller}/{command}"
        if parameters:
            url = f"{url}/{parameters}"                    
        return url


    def failure(self, message, status_code=""):
        self.log["failure"](message)
        self.error["error"] = message            
        return self.error


    def get(self, command, parameters="", module="", controller=""):
        url = self.check_url(command, module, controller, parameters)                                
        if url.startswith("ERROR:"):
            return self.failure(url)        
        req = requests.get(url, verify=self.verify, auth=self.auth)
        return self.check_response(req)


    def post(self, command, parameters="", payload="",
                                    module="", controller=""):
        url = self.check_url(command, module, controller, parameters)                                
        if url.startswith("ERROR:"):
            return self.failure(url)
        req = requests.post(url, json=payload, 
                                verify=self.verify, auth=self.auth)              
        return self.check_response(req)


    def test(self):
        response = self.get(
            command="status",
            module="core",
            controller="firmware"
        )                
        if "product" in response and "product_version" in response["product"]:
            return f" v{response["product"]["product_version"]}"
        else:
            self.ready = False        
            self.failure(
                f"API test failed ({self.base_url}/core/firmware/status)")
            return ""


class OpnSenseKeaSubnet:

    def __init__(self, logger, api, uuid, managed_description="", 
                                            force=False, strict=False):
        self.actions = []
        self.api = api
        self.force = force
        self.log = logger
        self.managed_description = managed_description
        self.prefix = ""
        self.ready = False
        self.settings = {}
        self.strict = strict            
        self.uuid = uuid
        if not uuid:
            self.log["failure"]("Subnet uuid cannot be empty")
            return
        if not self.api or not self.api.ready:
            self.log["failure"]("Cannot create subnet, API not ready")
            return            
        subnet = self.api.get("get_subnet", parameters=uuid)
        if not subnet or not"subnet4" in subnet:
            self.log["failure"](f"Cannot retrieve subnet with uuid {uuid}")
            return
        self.settings = subnet["subnet4"]
        self.prefix = self.settings["subnet"]
        self.ready = True
        self.log["success"](f"Subnet {self.prefix} ready!")


    def __str__(self):
        return self.prefix        


    def reservation_in_subnet(self, reservation):          
        if not reservation and not "subnet" in reservation:
            return False
        subnets = reservation["subnet"]
        if ([s for s, v in subnets.items() if v.get("selected") == 1][0] 
                                                                == self.uuid):
            return True            
        self.log["warning"](
            f"{reservation["ip_address"]} not in subnet {self.prefix}")
        return False


    def is_netbox_managed(self, res):
        if self.force:
            return res
        if not isinstance(res, list):
            if res["description"].startswith(self.managed_description):
                return res
            else:
                return None                
        return [r for r in res if r["description"].startswith(
            self.managed_description)]


    def create_action(self, action_type, payload={}, uuid=""):
        if action_type == "del" and uuid:
            action_log = uuid
        elif payload:
            if action_type == "set" and not uuid:
                return False
            action_log = payload
        else:
            return False
        action = {
            "action_type": action_type,
            "payload": payload,
            "uuid": uuid
        }            
        self.actions.append(action)
        self.log["debug"](f"{action_type} reservation: {action_log}")
        return True


    def create_payload(self, ip="", mac="", hostname="", description="",
                                                        reservation={}):
        if reservation:
            if not ip and "ip_address" in reservation:
                ip = reservation["ip_address"]
            if not mac and "mac_address" in reservation:
                mac = reservation["mac_address"]
            if not hostname and "hostname" in reservation:
                hostname = reservation["hostname"]
            if not description and "description" in reservation:
                description = reservation["description"]

        if not description:
            description = self.managed_description                                                     

        return {
            "reservation": {
                "subnet"     : self.uuid,
                "ip_address" : ip,
                "hw_address" : mac,
                "hostname"   : hostname,
                "description": description 
            }
        }


    def search_reservation(self, search_object, search_term, unique=True, 
                                                get_uuid=True, managed=True):
        if not search_object or not search_term:
            return None, False
        reservations = []
        duplicate = False
        payload = {"searchPhrase": search_term}
        results = self.api.post("search_reservation", payload=payload)
        if "rows" in results and results["rows"]:                   
            for reservation in results["rows"]:
                if (search_object in reservation and 
                    reservation[search_object] == search_term):
                    reservations.append(reservation)
        if not reservations:
            return None, False 
        if unique and len(reservations) != 1:
            duplicate = True
            self.log["warning"](
                f"Result for {search_term} not unique: {reservations}")          
        if managed:
            reservations = self.is_netbox_managed(reservations)         
        if get_uuid:
            reservations = [r.get("uuid") for r in reservations]
        return reservations, duplicate


    def get_reservation(self, ip="", mac="", uuid="", managed=True,
                                                    get_uuid = False):        
        if ip:                
            uuids, duplicate = self.search_reservation(
                                    "ip_address", ip, managed=False)
            if duplicate:
                self.log["failure"](f"Duplicate IP {ip}")                                                
                return None, True                                   
            if uuids:
                uuid = uuids[0]
        if mac:               
            uuids_mac, duplicate = self.search_reservation(
                                    "hw_address", mac, managed=False)
            if duplicate:
                self.log["failure"](f"Duplicate MAC {mac}")                                  
                return None, True
            if uuids_mac:                
                if uuid and uuids_mac[0] != uuid:
                    self.log["failure"](f"Conflicting ip/mac {ip} {mac}")
                    return None, True
                uuid = uuids_mac[0]
        if uuid:                
            result = self.api.get("get_reservation", parameters=uuid)                
            if result and "reservation" in result:                    
                if (not managed or 
                        self.is_netbox_managed(result["reservation"])):
                    if self.reservation_in_subnet(result["reservation"]):
                        if get_uuid:
                            return uuid, False
                        result["reservation"]["uuid"] = uuid
                        return result["reservation"], False
                    else:
                        return None, True                      
                else:
                    self.log["warning"](
                        f"Reservation not managed {uuid}")                        
                    return None, True
        return None, False


    def get_reservations(self, get_uuid=False):            
        reservations, duplicate = self.search_reservation(
                                    search_object="subnet",
                                    search_term=self.prefix,
                                    get_uuid=get_uuid,
                                    unique=False)
        return reservations


    def add_reservation(self, ip="", mac="", hostname="", description=""):
        if not ip or not mac:
            self.log["failure"]("Invalid or missing ip/mac")
            return False        
        reservation, error = self.get_reservation(ip, mac, managed=False)
        if error:                
            return False         
        if not reservation:            
            payload = self.create_payload(ip, mac, hostname, description)
            self.log["info"](f"Add reservation {ip} {mac} to {self.prefix}")
            return self.create_action("add", payload=payload)               
        self.log["warning"](
                    f"Reservation already exists: {ip} {mac}")
        if not self.strict:
            return self.set_reservation(ip, mac, hostname, description)                   
        return True


    def del_reservation(self, ip="", mac="", uuid=""):
        action_log = uuid if uuid else f"{ip} {mac}"        
        managed = False if self.force else True
        uuid, error = self.get_reservation(ip, mac, uuid, managed=managed,
                                                            get_uuid=True)
        if error:
            return False
        if not uuid:
            self.log["warning"](
                f"Trying to delete a non-existing reservation {action_log}")
            return True
        self.log["info"](f"Delete reservation {action_log} in {self.prefix}")
        return self.create_action("del", uuid=uuid)


    def set_reservation(self, ip="", mac="", hostname="", description="",
                                                    uuid="", is_sync=False):
        action_log = uuid if uuid else f"{ip} {mac}"
        reservation, error = self.get_reservation(ip, mac, uuid, managed=True)
        if error:
            return False
        if reservation:              
            payload = self.create_payload(ip, mac, hostname,
                                        description, reservation)
            self.log["info"](f"Update reservation {ip} {mac} in {self.prefix}")
            return self.create_action("set", payload=payload,
                                            uuid=reservation["uuid"])
        error_level = "debug" if is_sync else "warning"
        self.log[error_level](
            f"Trying to modify a non-existing reservation {action_log}")
        if not self.strict and not reservation:
            return self.add_reservation(ip, mac, hostname, description)        
        return True


    def purge_subnet(self):
        reservation_uuids = self.get_reservations(get_uuid=True)
        if reservation_uuids:
            for uuid in reservation_uuids:
                self.del_reservation(uuid=uuid)
        return True                


    def commit(self, dry_run=False):        
        if not self.ready:
            self.log["failure"](
                f"Cannot commit changes in {self.prefix}: subnet not ready")
            return False
        if dry_run or not self.actions:
            return True
        for action in self.actions:
            action_type = action["action_type"]                
            response = self.api.post(command=f"{action_type}_reservation",
                                        parameters=action["uuid"],
                                        payload=action["payload"]
                                    )
            self.log["debug"](f"Response: {response}")
            if "error" in response:
                self.log["failure"](
                    f"Err: {action_type} {len(self.actions)} reservations")
                return False
        self.log["success"](
            f"Committed {len(self.actions)} actions in {self.prefix}")
        return True


class NetboxOpnSenseKeaSyncScript(Script):   
    opn_api_base_url = StringVar(
        default = "",
        description = "OPNsense base API URL",
        label = "API URL",
        required = True
    )

    opn_api_key = StringVar(  
        default = "",  
        description = "OPNsense API Key",
        label = "API Key",
        required = True
    )

    opn_api_secret = StringVar(  
        default = "",  
        description = "OPNsense API Secret",
        label = "API Secret",
        required = True
    )

    opn_api_verify_ssl = BooleanVar(
        default = True,
        description = "Verify API SSL",
        label = "Verify SSL",
        required = False
    )

    opn_api_test = BooleanVar(
        default = True,
        description = "Test the API by getting the version of OPNsense",
        label = "Test API",
        required = False
    )    

    opn_kea_action = ChoiceVar(
        default = "sync",
        description = "Action to perform",
        label = "Action",
        required = False,
        choices = (
            ("sync", "Sync subnets"),        
            ("purge", "Purge subnets"),  
        )       
    )

    opn_kea_allowed_prefixes = MultiObjectVar(
        default = [],
        description = "Prefixes to update",
        label = "Prefixes",
        model = Prefix,
        required = False,        
    )

    opn_kea_managed_description = StringVar(
        default = "Netbox managed",
        description = "Description indicating object is Netbox managed",
        label = "Description",
        required = False
    )

    opn_kea_filter_prefix_include_status = MultiChoiceVar(
        default = [],
        description = "Prefix status to include",
        label = "Include Status",
        required = False,
        choices = PrefixStatusChoices       
    ) 

    opn_kea_filter_prefix_exclude_status = MultiChoiceVar(
        default = [],
        description = "Prefix status to exclude",
        label = "Exclude Status",
        required = False,
        choices = PrefixStatusChoices
    )   

    netbox_prefix_roles_choices = []
    for role in Role.objects.all():        
        netbox_prefix_roles_choices.append(
            (role.id, role.name)
        )
    opn_kea_filter_prefix_include_role = MultiChoiceVar(
        default = [],
        description = "Prefix roles to include",
        label = "Include Roles",
        required = False,
        choices = netbox_prefix_roles_choices
    ) 
    
    opn_kea_filter_prefix_exclude_role = MultiChoiceVar(
        default = [],
        description = "Prefix roles to exclude",
        label = "Exclude Roles",
        required = False,
        choices = netbox_prefix_roles_choices
    )

    opn_kea_set_hostname = BooleanVar(
        default = True,
        description = "Set hostname in reservation from IP DNS name",
        label = "Hostname",
        required = False
    )

    opn_kea_strict = BooleanVar(
        default = False,
        description = "Strict add/update actions (e.g. don't add when setting non-existing object)",
        label = "Strict",
        required = False
    )

    opn_kea_dry_run = BooleanVar(
        default = False,
        description = "Test only, no commits",
        label = "Dry run",
        required = False
    )

    opn_kea_force = BooleanVar(
        default = False,
        description = "Ignores the netbox managed description check",
        label = "Force",
        required = False
    )    

    class Meta:
        name = "Netbox OPNsense Kea sync script"
        description = "Synchronize OPNsense hosted Kea DHCP server with Netbox data"

    params = None

    class NetboxOpnSenseKeaParameters:
        def __init__(self, logger, data):
            self.action = "set"            
            self.api = None
            self.dataset = {}
            self.filters = {}
            self.filter_actions = ["include", "exclude"]
            self.filter_targets = ["ip", "prefix"]            
            self.log = logger
            self.subnet_settings = {}            
            self._valid = False

            if ("custom_fields" in data 
                and isinstance(data["custom_fields"], dict)):
                data = data | data["custom_fields"]           

            self.settings = {
                "action": "",
                "allowed_prefixes": [],
                "dry_run": False,
                "force": False,
                "managed_description": "Netbox managed",
                "set_hostname": True,
                "strict": False
            }
            for key in self.settings:
                settings_key = "opn_kea_" + key
                if settings_key in data and data[settings_key]:
                    self.settings[key] = data[settings_key]

            if self.settings["action"]:
                if self.settings["action"] not in [
                    "add", "del", "purge", "set", "sync"]:
                    self.log["failure"](f"Invalid action {self.action}")
                    return
                self.action = self.settings["action"]

            # Setup the API
            api_settings = {                
                "base_url": "",
                "controller": "dhcpv4",
                "key": "",
                "logger": self.log,
                "module": "kea",
                "secret": "",
                "test": True,
                "verify_ssl": True
            }
            for key in api_settings:
                api_settings_key = "opn_api_" + key
                if api_settings_key in data and data[api_settings_key]:
                    api_settings[key] = data[api_settings_key]            
            self.api = NetboxOpnSenseAPIClient(api_settings)
            if not self.api or not self.api.ready:
                return                              

            # Get relevant data of object to change
            object_data = {
                "id": 0,
                "address": "",
                "description": "",
                "end_address": "",
                "prefix": "",
                "primary_mac_address": "",
                "start_address": ""
            }
            for key in object_data:
                if key in data and data[key]:
                    object_data[key] = data[key]

            # Get prefix/ip filters        
            self.get_filters(data)

            # Subnet sync/purge
            if self.action in ["purge", "sync"]:                
                self.get_prefixes()

            # Handle single reservation
            elif object_data["address"] or ( 
                object_data["primary_mac_address"] and 
                object_data["id"]):
                self.action = self.action + "_reservation"
                if not object_data["address"]:                
                    object_data["address"] = str(IPAddress.objects.get(
                        assigned_object_id=object_data["id"]))
                    if not object_data["address"]:
                        self.log["failure"]("No IP found")
                        return
                self.get_prefixes(ip=object_data["address"])
            
            else:
                # Handle ip-range changes as parent subnet's zones update 
                if object_data["start_address"] and object_data["end_address"]:
                    prefixes = Prefix.objects.filter(
                    prefix__net_contains_or_equals=object_data["start_address"]
                    )
                    if not prefixes or len(prefixes) != 1:
                        self.log["failure"](
                            f"Prefix for {object_data["start_address"]} -" +
                            f"{object_data["end_address"]} not found")
                        return
                    object_data["prefix"] = str(prefixes[0])                
                    self.action = "set"                    

                # Handle subnet updates
                if object_data["prefix"]:
                    self.action = self.action + "_subnet"
                    description = self.settings["managed_description"] 
                    if object_data["description"]:
                        description += f" {object_data["description"]}"
                    self.get_subnet_settings(
                        data, object_data["prefix"], description)
                    self.get_prefixes()

                else:
                    self.log["failure"](f"Invalid action {self.action}")
                    return            

            if self.filters:
                self.log["debug"](f"Active filters: {self.filters}")
            
            if not self.dataset:                
                self.log["warning"]("No matching objects to perform action")
                return            
            
            if self.settings["force"]:
                self.log["warning"]("FORCE enabled!")

            self.log["info"](f"Starting action: {self.action}")
            self._valid = True


        @property
        def is_valid(self):
            return self._valid


        def add_filter(self, filters, target, action, attr, values):
            if (not attr or not values):
                return filters
            if not isinstance(values, list):
                values = values.split(",")
            filters[target][action][f"{attr}__in"] = values            
            return filters


        def get_filters(self, data):
            for target in self.filter_targets:
                self.filters[target] = {}
                for action in self.filter_actions:
                    self.filters[target][action] = {}
                    filter_key = f"opn_kea_filter_{target}_{action}"
                    if (filter_key in data and 
                    isinstance(data[filter_key], dict)):
                        for attr, values in data[filter_key].items():
                            self.add_filter(self.filters, 
                                target=target, 
                                action=action, 
                                attr=attr, 
                                values=values)
                    for attr in ["role", "status"]:
                        filter_key = f"{filter_key}_{attr}"
                        if filter_key in data and data[filter_key]:
                                self.add_filter(self.filters, 
                                    target=target, 
                                    action=action, 
                                    attr=attr, 
                                    values=data[filter_key])            


        def get_kea_subnet(self, prefix):
            kea_sub = None
            kea_subs = self.api.post("search_subnet", payload={
                                            "searchPhrase": prefix})

            if kea_subs and "rows" in kea_subs and len(kea_subs["rows"]) == 1:
                kea_sub = kea_subs["rows"][0]
            elif (self.action in ["add_subnet", "delete_subnet"] or 
                (self.action == "update_subnet"
                    and not self.settings["strict"])):
                return None, "no_match_continue"
            else:
                self.log["warning"](
                        f"Could not find matching Kea subnet for {prefix}")
                return None, "no_match"
            
            if (not self.settings["force"] and 
                (not "description" in kea_sub or not
                kea_sub["description"] or not
                kea_sub["description"].startswith(
                                self.settings["managed_description"]))):
                    self.log["warning"](
                        f"Subnet {prefix} not managed by Netbox")
                    return None, "not_managed"

            subnet = OpnSenseKeaSubnet(
                logger=self.log,
                api=self.api,
                uuid=kea_sub["uuid"],
                managed_description=self.settings["managed_description"],
                force=self.settings["force"],
                strict=self.settings["strict"],
            )

            if subnet and subnet.ready:
                return subnet, "success"

            self.log["failure"](f"Failed to add subnet: {prefix}")

            return None, "error"

            
        def get_prefixes(self, ip=""):
                      
            prefix_filters = self.filters["prefix"]["include"]
            prefix_exclusions = self.filters["prefix"]["exclude"]
            reservations = []

            if ip:
                prefix_filters["prefix__net_contains_or_equals"] = ip
            if self.settings["allowed_prefixes"]:
                prefix_filters["prefix__in"] = [
                    str(prefix) for prefix in self.settings["allowed_prefixes"]
                    ]

            obj_prefixes = Prefix.objects.filter(**prefix_filters).exclude(
                                                        **prefix_exclusions)

            if not obj_prefixes:
                self.log["warning"](f"No valid prefixes found")
                return

            for obj_prefix in obj_prefixes:
                
                prefix = str(obj_prefix)                
                subnet, err = self.get_kea_subnet(prefix)

                if not subnet and not err == "no_match_continue":                    
                    continue
                
                if self.action in [ "add_subnet", "set_subnet"]:
                    self.subnet_settings["subnet4"]["pools"] = \
                        self.get_pools(obj_prefix)

                if self.action != "del_subnet":                  
                    reservations = self.get_ip_reservations(obj_prefix, ip)
                    if ip and not reservations:
                        reservations = self.get_ip_reservations(obj_prefix, ip,
                                                                filtered=False)
                        if reservations:
                            self.action = "del_reservation"

                self.dataset[prefix] = {
                    "reservations": reservations,
                    "subnet": subnet
                }

            self.log["debug"](f"Records to update: {self.dataset}")


        def get_ip_reservations(self, obj_prefix, ip, filtered=True):
            
            ip_filters = {}
            ip_exclusions = {}
            ip_reservations = []

            if filtered:
                ip_exclusions = self.filters["ip"]["exclude"]
                ip_filters = self.filters["ip"]["include"]

            if ip:
                ip_filters["address"] = ip
            else:
                ip_filters["address__in"] = [
                    str(ip) for ip in obj_prefix.get_child_ips()]

            obj_ips = IPAddress.objects.filter(**ip_filters).exclude(
                                                        **ip_exclusions)

            if not obj_ips:
                self.log["warning"](f"No valid ips found in {obj_prefix}")
                return []

            for obj_ip in obj_ips:
                host = ""
                obj_if = None
                
                if obj_ip.assigned_object_id:
                    if obj_ip.assigned_object_type.model == "interface":
                        obj_if = Interface.objects.get(
                            id=obj_ip.assigned_object_id)
                    elif obj_ip.assigned_object_type.model == "vminterface":
                        obj_if = VMInterface.objects.get(
                            id=obj_ip.assigned_object_id)                        
                if not obj_if:
                    self.log["debug"](
                        f"Skipping IP {obj_ip}: no valid interface")
                    continue
                if hasattr(obj_if, "primary_mac_address"):
                    mac = obj_if.primary_mac_address
                else:
                    self.log["debug"](
                        f"Skipping IP {obj_ip}: no mac at iface {obj_if}")
                    continue

                if self.settings["set_hostname"] and obj_ip.dns_name:
                    host, _, _ = str(obj_ip.dns_name).partition(".")                    

                ip_reservations.append({                        
                    "ip"       : str(obj_ip.address.ip),
                    "hostname" : host,
                    "mac"      : str(mac).lower(),
                })

            return ip_reservations


        def get_pools(self, obj_prefix):            
            if obj_prefix:
                obj_pools = obj_prefix.get_child_ranges()
                if obj_pools:
                    arr_pools = []
                    for pool in obj_pools:
                        arr_pools.append(
                            f"{pool.start_address.ip}-{pool.end_address.ip}")
                    if arr_pools:
                        self.log["info"](
                            f"Prefix {obj_prefix} pools: {arr_pools}")
                        return "\n".join(arr_pools)
            return ""

        def get_subnet_settings(self, data, prefix, description):
            option_data = {
                "boot_file_name": "",
                "domain_name_servers": "",
                "domain_name": "",
                "domain_search": "",
                "ntp_servers": "",
                "routers": "",
                "static_routes": "",
                "time_servers": "",
                "tftp_server_name": "",
                "v6_only_preferred": ""
            }
            for key in option_data:
                option_key = "opn_kea_opt_" + key
                if option_key in data and data[option_key]:
                    option_data[key] = data[option_key]
       
            self.subnet_settings = {
                "subnet4": {
                    "description": description,
                    "match-client-id": "",
                    "next_server": "",
                    "option_data": option_data,                   
                    "option_data_autocollect": "",
                    "pools": "",
                    "subnet": str(prefix)
                }
            }
            for key, value in self.subnet_settings["subnet4"].items():
                subnet_key = "opn_kea_sub_" + key
                if subnet_key in data and data[subnet_key]:                   
                    self.subnet_settings["subnet4"][key] = data[subnet_key]
                    
            self.settings["allowed_prefixes"] = [str(prefix)]                                    


    def get_logger(self):
        return {
            "success" : self.log_success,
            "debug"   : self.log_debug,
            "info"    : self.log_info,
            "warning" : self.log_warning,
            "failure" : self.log_failure,
        }


    def create_subnet_update_request(self, prefix, subnet, action="set"):

        payload = self.params.subnet_settings

        if subnet:
            if action == "add":
                self.log_warning(f"Subnet {prefix} already exists")
                if self.params.settings["strict"]:
                    return None
                action = "set"
                                    
            for setting, value in payload["subnet4"].items():
                if not value and setting != "option_data":
                    payload["subnet4"][setting] = subnet.settings[setting]

            subnet_options = subnet.settings["option_data"]
            for option, value in payload["subnet4"]["option_data"].items():
                if not value and not isinstance(subnet_options[option], dict):
                    payload["subnet4"][
                        "option_data"][option] = subnet_options[option]
        else:
            if action == "set":
                self.log_warning(f"Updating non-existing subnet {prefix}")
                if self.params.settings["strict"]:
                    return None
                action = "add"
            if not payload["subnet4"]["option_data_autocollect"]:
                payload["subnet4"]["option_data_autocollect"] = "0"
            if not payload["subnet4"]["match-client-id"]:
                payload["subnet4"]["match-client-id"] = "0"

        if payload["subnet4"]["option_data_autocollect"] == "1":
            payload["subnet4"]["option_data"]["domain_name_servers"] = ""
            payload["subnet4"]["option_data"]["ntp_servers"] = ""
            payload["subnet4"]["option_data"]["routers"] = ""

        return {
            "action" : action,
            "payload": payload,            
        }


    def add_subnet(self, prefix, subnet, request={}):

        if not request:
            request = self.create_subnet_update_request(prefix, subnet,
                                                        action="add")

        if request:
            if "action" in request and request["action"] == "set":
                return self.set_subnet(prefix, subnet, request)
        else:            
            self.log_failure(f"Failed to add subnet")
            return False

        self.log_info(f"Creating subnet {prefix}")

        if not self.params.settings["dry_run"]:
            error = ""            
            response = self.params.api.post("add_subnet", 
                                    payload=request["payload"])

            if "error" in response and response["error"]:
                error = response["error"]
            if not "result" in response or not response["result"] == "saved":
                self.log_failure(f"Failed to add subnet {prefix} {error}")
                return False

        if not self.add_reservations():
            return False                

        self.log_success(f"Created subnet {prefix}")
        
        return True


    def del_subnet(self, prefix, subnet):

        self.log_info(f"Deleting subnet {prefix}")
        
        z = prefix["subnet"]
        if not subnet:
            self.log_warning(f"Cannot delete non-existing subnet {prefix}")
            return False

        if not self.params.settings["dry_run"]:
            error = ""
            response = self.params.api.post("del_subnet",
                                            parameters=subnet.uuid)

            if "error" in response and response["error"]:
                error = response["error"]
            if not "result" in response or not response["result"] == "deleted":
                self.log_failure(f"Failed to delete subnet {prefix} {error}")
                return False                                            
        
        self.log_success(f"Deleted subnet {prefix}")

        return True


    def set_subnet(self, prefix, subnet, request={}):

        if not request:
            request = self.create_subnet_update_request(prefix, subnet,
                                                        action="set")

        if request:
            if "action" in request and request["action"] == "add":
                return self.add_subnet(prefix, subnet, request)
        else:
            self.log_failure(f"Failed to update subnet {prefix}")
            return False

        self.log_info(f"Updating subnet {prefix}")        

        if not self.params.settings["dry_run"]:
            error = ""
            response = self.params.api.post("set_subnet",
                                    parameters=subnet.uuid,
                                    payload=request["payload"])
            
            if "error" in response and response["error"]:
                error = response["error"]
            if not "result" in response or not response["result"] == "saved":
                self.log_failure(f"Failed to set subnet {prefix} {error}")
                return False

        if not self.set_reservations(is_sync=True):
            return False

        self.log_success(f"Updated subnet {prefix}")        

        return True


    def purge_subnets(self):        
        for prefix in self.params.dataset.values():
            purge_ok = False
            if prefix["subnet"].purge_subnet():
                if (self.params.settings["dry_run"] or 
                    prefix["subnet"].commit()):
                    purge_ok = True
            if not purge_ok:
                return False            
        return True


    def add_reservations(self, description=""):
        for prefix in self.params.dataset.values():            
            for reservation in prefix["reservations"]:
                if not prefix["subnet"].add_reservation(
                    ip=reservation["ip"],
                    hostname=reservation["hostname"],
                    mac=reservation["mac"],
                    description=description,                    
                ):
                    return False
            if (not self.params.settings["dry_run"]
                and not prefix["subnet"].commit()):
                return False
        return True


    def del_reservations(self):
        for prefix in self.params.dataset.values():
            for reservation in prefix["reservations"]:
                if not prefix["subnet"].del_reservation(
                    ip=reservation["ip"],                    
                    mac=reservation["mac"]
                ):
                    return False
            if (not self.params.settings["dry_run"]
                and not prefix["subnet"].commit()):
                return False                  
        return True


    def set_reservations(self, description="", is_sync=False):
        for prefix in self.params.dataset.values():            
            for reservation in prefix["reservations"]:
                if not prefix["subnet"].set_reservation(
                    ip=reservation["ip"],
                    hostname=reservation["hostname"],
                    mac=reservation["mac"],
                    description=description,
                    is_sync=is_sync
                ):
                    return False
            if (not self.params.settings["dry_run"]
                and not prefix["subnet"].commit()):
                return False
        return True


    def run(self, data, commit=True):

        logger = self.get_logger()
        self.params = self.NetboxOpnSenseKeaParameters(logger, data)

        if not self.params or not self.params.is_valid:
            return("FAILURE")

        match self.params.action:
            case "add_subnet":                
                for prefix, data in self.params.dataset.items():
                    if not self.add_subnet(prefix, data["subnet"]):
                        return("FAILURE")                    
            case "del_subnet":
                for prefix, data in self.params.dataset.items():                    
                    if not self.del_subnet(prefix, data["subnet"]):
                        return("FAILURE")                    
            case "set_subnet":
                for prefix, data in self.params.dataset.items():
                    if not self.set_subnet(prefix, data["subnet"]):
                        return("FAILURE")                    
            case "add_reservation":
                if not self.add_reservations():
                    return("FAILURE")
            case "del_reservation":
                if not self.del_reservations():
                    return("FAILURE")                                  
            case "set_reservation":
                if not self.set_reservations():
                    return("FAILURE")
            case "purge":
                if not self.purge_subnets():
                    return("FAILURE")
            case "sync":
                if not self.set_reservations(is_sync=True):
                    return("FAILURE")                        
            case _:
                return("FAILURE")

        if self.params.settings["dry_run"]:
            status = self.params.api.post(
                command="reconfigure",
                parameters="",
                payload={},
                module="kea",
                controller="service"
                )

            if (not status
                or not "status" in status
                or not status["status"] == "ok"):
                self.log_failure("Error reconfiguring Kea service")
                return("FAILURE")
       
        return("SUCCESS")
