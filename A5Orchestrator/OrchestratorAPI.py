# reference for the package Swagger UI 
import logging
import requests
import json
import codecs
import pandas as pd


logging.basicConfig()

class Orchestrator(object):
    def __init__(self):
        """
        Initialization of Orchestrator object and will create a pointer to access orchestrator
        """
        self.source_url = None 
        self.tenancy_name = None
        self.password = None
        self.username = None
        self.status = True
        self.error = None
        self.access_key = None

    def orchestrator_connect(self,tenancy_name,username,password):
        """ Authenticates the user based on user name and password

        Args:
            tenancy_name (string): Tenancy name 
            username (string): User name or Email id 
            password (string): Password
        """

        self.tenancy_name = tenancy_name
        self.username = username
        self.password = password
        
        url = self.source_url+"/api/Account/Authenticate"
        data = {"tenancyName": self.tenancy_name,
                "usernameOrEmailAddress": self.username,
                "password": self.password}
        logging.info(f"Making orchestrator service connection to {url}")
        responce = requests.post(url,data)
        if(responce.status_code == 200):
            responce_json = responce.json()
            self.access_key = responce_json["result"]
            logging.info(f"Connection established for Orchestrator service")
        else:
            logging.error(f'Something went wrong while connecting to Orchestrator(orchestrator_connect). Check Logs...')
            logging.error(f'Error while connecting: {responce.status_code}')
            self.status = False

    def get_api_call(self,url,OrganizationUnitId = None):
        """ Helps to perform GET operations

        Args:
            url (string): Rest API URl to perform GET operation
            OrganizationUnitId (int, optional): Organization or Folder id. Defaults to None.

        Returns:
            [dic]: responce from requested URL
        """
        try:
            head = {
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.access_key
            }
            if OrganizationUnitId != None:
                head['X-UIPATH-OrganizationUnitId'] = str(OrganizationUnitId)

            responce = requests.get(url,headers=head)
            
            if(responce.status_code == 200):
                return responce.json()
            else:
                self.status = False
                return responce.status_code
        except Exception as e :
            logging.error(f'Something went wrong while connecting to Orchestrator(get_api_call). Check Logs...')
            logging.error('Error while connecting: {}'.format(str(e)))
            self.status = False
            return False

    def post_api_call(self,url,data = None,OrganizationUnitId = None):
        """ Helps to perform POST operations

        Args:
            url (string): Rest API URl to perform POST operation
            data ([dic], optional): [description]. Data if any ,Defaults to None.
            OrganizationUnitId (int, optional): Organization or Folder id. Defaults to None.

        Returns:
            [dic]: responce from requested URL
        """
        try:
            head = {
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.access_key
            }
            if OrganizationUnitId != None:
                head['X-UIPATH-OrganizationUnitId'] = OrganizationUnitId
            if data == None:
                responce = requests.post(url,headers=head)
            else:
                responce = requests.post(url,headers=head,data=json.dumps(data))

            if(responce.status_code == 200):
                return responce.json()
            else:
                self.status = False
                return responce.status_code
        except Exception as e :
            logging.error(f'Something went wrong while connecting to Orchestrator(post_api_call). Check Logs...')
            logging.error('Error while connecting: {}'.format(str(e)))
            self.status = False
            return False

    def get_users(self,user_id = None):
        """ Gets Users.
        
        Args:
            user_id (int,optional): User id for the user

        Required permissions:
            Users.View.
        """

        if user_id != None:
            url  = self.source_url+f"/odata/Users({user_id})"
        else:
            url  = self.source_url+f"/odata/Users"
        responce = self.get_api_call(url)
        return responce
    
    def create_user(self,user_information):
        """ Creates a new user.

        Required permissions:
            Users.Create.
        
         Args:
            user_information ([dic]): user_information must consist of  
                Name (string, optional): The name of the person for which the user is created. stringMax. Length:64,
                Surname (string, optional): The surname of the person for which the user is created. stringMax. Length:64,
                UserName (string, optional): The name used to login to Orchestrator. ,
                Domain (string, optional): The domain from which the user is imported ,
                FullName (string, optional): The full name of the person constructed with the format Name Surname. ,
                EmailAddress (string, optional): The e-mail address associated with the user. stringMax. Length:256,
                IsEmailConfirmed (boolean, optional): States if the email address is valid or not. ,
                LastLoginTime (string, optional): The date and time when the user last logged in, or null if the user never logged in. ,
                IsActive (boolean, optional): States if the user is active or not. An inactive user cannot login to Orchestrator. ,
                CreationTime (string, optional): The date and time when the user was created. ,
                AuthenticationSource (string, optional): The source which authenticated this user. ,
                Password (string, optional): The password used during application login. ,
                IsExternalLicensed (boolean, optional),
                UserRoles (Array[UserRoleDto], optional): The collection of roles associated with the user. ,
                RolesList (Array[string], optional): The collection of role names associated with the user. ,
                LoginProviders (Array[string], optional): The collection of entities that can authenticate the user. ,
                OrganizationUnits (Array[OrganizationUnitDto], optional): The collection of organization units associated with the user. ,
                TenantId (integer, optional): The id of the tenant owning the user. ,
                TenancyName (string, optional): The name of the tenant owning the user. ,
                TenantDisplayName (string, optional): The display name of the tenant owning the user. ,
                TenantKey (string, optional): The key of the tenant owning the user. ,
                Type (string, optional): The user type. = ['User', 'Robot', 'DirectoryUser', 'DirectoryGroup']stringEnum:"User", "Robot", "DirectoryUser", "DirectoryGroup",
                ProvisionType (string, optional): The user type. = ['Manual', 'Automatic']stringEnum:"Manual", "Automatic",
                LicenseType (string, optional): The user's license type. = ['NonProduction', 'Attended', 'Unattended', 'Studio', 'Development', 'StudioX']stringEnum:"NonProduction", "Attended", "Unattended", "Studio", "Development", "StudioX",
                RobotProvision (RobotProvisionDto, optional): Robot provisioning settings ,
                NotificationSubscription (UserNotificationSubscription, optional): User can choose which notifications does he want to receive ,
                Key (string, optional): Unique key for a user ,
                MayHaveUserSession (boolean, optional): Specifies whether this user is allowed to have a User session (default: true) ,
                MayHaveRobotSession (boolean, optional): Specifies whether this user is allowed to have an attached Robot session (default: true) ,
                BypassBasicAuthRestriction (boolean, optional): Specifies whether this user bypasses the "Auth.RestrictBasicAuthentication" application setting (default: false) ,
                Id (integer, optional)
                
                UserRoleDto (dic)
                    UserId (integer, optional): The Id of the associated user. ,
                    RoleId (integer, optional): The Id of the associated role. ,
                    UserName (string, optional): The name of the associated user ,
                    RoleName (string, optional): The name of the associated role ,
                    Id (integer, optional)
                OrganizationUnitDto (dic)
                    DisplayName (string): The name of the organization unit. ,
                    Id (integer, optional)
                RobotProvisionDto (dic)
                    UserName (string, optional): The UserName used to authenticate on the Host Machine. ,
                    ExecutionSettings (inline_model_9, optional): An object containing execution settings for the Robot. ,
                    RobotId (integer, optional): The actual Id of the provisioned Robot. ,
                    RobotType (string, optional): The actual Type of the provisioned Robot. = ['NonProduction', 'Attended', 'Unattended', 'Studio', 'Development', 'StudioX']stringEnum:"NonProduction", "Attended", "Unattended", "Studio", "Development", "StudioX"
                UserNotificationSubscription (dic)
                    Queues (boolean, optional),
                    Robots (boolean, optional),
                    Jobs (boolean, optional),
                    Schedules (boolean, optional),
                    Tasks (boolean, optional),
                    QueueItems (boolean, optional)
        """    
        url  = self.source_url+"/odata/Users"
        responce = self.post_api_call(url,user_information)
        return responce


    def delete_user(self,user_id):
        """ Deletes a user
        
        Required permissions:
            Users.Delete.
        
        Args:
            user_id (int): User id for the user going to delete
        
        Returns:
            [boolen]: True if deleted, False if not deteted
        """

        url  = self.source_url+f"/odata/Users({user_id})"
        responce = self.delete_api_call(url)
        if responce == 204:
            return True
        else:
            return False

    def get_current_permisions(self):
        """
        Returns a user permission collection containing data about the current user and all the permissions it has.

        Returns:
            [Dic]: data consist of userid and permission 
        """

        url  = self.source_url+"/odata/Users/UiPath.Server.Configuration.OData.GetCurrentPermissions()"
        responce = self.get_api_call(url)
        return responce

    def get_current_loggedin_users(self):
        """
        Returns details about the user currently logged into Orchestrator.
        """

        url  = self.source_url+"/odata/Users/UiPath.Server.Configuration.OData.GetCurrentUser()"
        responce = self.get_api_call(url)
        return responce

    def get_user_login_attempts(self,user_id):
        """Gets the user's login attempts

        Args:
            user_id (int): Id of the user

        Returns:

        ODataResponse[List[UserLoginAttemptDto]] 
            @odata.context (string, optional),
            value (Array[UserLoginAttemptDto], optional)
        
        UserLoginAttemptDto (list)
            CreationTime (string, optional): The date and time when the action was performed. ,
            ClientIpAddress (string, optional): Client IP Address ,
            ClientName (string, optional): Client name ,
            BrowserInfo (string, optional): Browser Information ,
            Result (string, optional): The login's attempt result = ['Success', 'InvalidUserNameOrEmailAddress', 'InvalidPassword', 'UserIsNotActive', 'InvalidTenancyName', 'TenantIsNotActive', 'UserEmailIsNotConfirmed', 'UnknownExternalLogin', 'LockedOut', 'UserPhoneNumberIsNotConfirmed']stringEnum:"Success", "InvalidUserNameOrEmailAddress", "InvalidPassword", "UserIsNotActive", "InvalidTenancyName", "TenantIsNotActive", "UserEmailIsNotConfirmed", "UnknownExternalLogin", "LockedOut", "UserPhoneNumberIsNotConfirmed"],
            UserId (integer, optional): The user that authenticated ,
            Id (integer, optional)
        """

        url  = self.source_url+f"/odata/UserLoginAttempts({user_id})"
        responce = self.get_api_call(url)
        return responce
    
    def toggle_role(self,role,toggle,user_id):
        """Associates/dissociates the given user with/from a role based on toggle parameter.

        Required permissions: 
            Users.Edit.
        
        Args:
            role (string): The name of the role to be associated/dissociated.
            toggle (string): States whether to associate or to dissociate the role with/from the user.
            user_id(int): Id for the user

        Returns:
            [boolen]: True if executed, False if not executed
        """

        url  = self.source_url+f"/odata/Users({user_id})/UiPath.Server.Configuration.OData.ToggleRole"
        data = {"role":role,"toggle":toggle}
        responce = self.post_api_call(url,data)
        if responce == 200:
            return True
        else:
            return False 
    
    def import_user_from_AD(self,organizationUnitIds,group = None,domain = None,role_list = None):
        """ Imports from AD all users from the given group and associates them with given roles.

        Args:
            organizationUnitIds (Array[integer]): The collection of ids of the organization units the imported users will be associated with
            group (string, optional): The name of the AD group whose users are to be imported
            domain (string, optional): 
            role_list (Array[string], optional): The collection of roles the imported users will be associated with.

        Returns:
            [boolen]: True if executed, False if not executed
        """

        url  = self.source_url+f"/odata/Users/UiPath.Server.Configuration.OData.ImportUsers"        
        data = {}
        if group != None:
            data["group"] = group
        if domain != None:
            data["domin"] = domain
        if role_list != None:
            data["roleslist"] = role_list
        if organizationUnitIds != None:
            data["organizationUnitIds"]: organizationUnitIds

        responce = self.post_api_call(url,data)
        if responce == 201:
            return True
        else:
            return False 

    def alter_organization_access(self,user_id,organizationUnitId,toggle):
        """Associates/dissociates the given user with/from an organization unit based on toggle parameter

        Args:
            user_id (int): Id for the user
            organizationUnitId (int): The id of the organization unit to be associated/dissociated.
            toggle (boolean): States whether to associate or to dissociate the organization unit with/from the user.

        Returns:
            [boolen]: True if executed, False if not executed
        """

        url  = self.source_url+f"/odata/Users({user_id})/UiPath.Server.Configuration.OData.ToggleOrganizationUnit"
        data = {"organizationUnitId":organizationUnitId,"toogle":toggle}
        responce = self.post_api_call(url,data)
        if responce == 200:
            return True
        else:
            return False  
    
    def change_password(self,user_id,current_password,new_password):
        """ Changes the password of the user.

        Args:
            user_id (int): Id for the user
            current_password (string): Existing user password
            new_password (string): The new user password
        """
        url  = self.source_url+f"/odata/Users({user_id})/UiPath.Server.Configuration.OData.ChangePassword"
        data = {"CurrentPassword":current_password,"NewPassword":new_password}
        responce = self.post_api_call(url,data)
        if responce == 200:
            return True
        else:
            return False 

    def activate_diactive_user(self,user_id,status):
        """ Activate or deactivate a user

        Args:
            user_id (int): Id for the user
            status (boolean): status yet to change
        Returns:
            [boolen]: True if executed, False if not executed
        """
        url  = self.source_url+f"/odata/Users({user_id})/UiPath.Server.Configuration.OData.SetActive"
        data = {"activate":status}
        responce = self.post_api_call(url,data)
        if responce == 200:
            return True
        else:
            return False 

    def change_culture(self,culture,user_id = None):
        """ Changes the culture for the current user or specified user 

        Args:
            culture (string): 
            user_id (int,optional): Id for the user,default current user
        Returns:
            [boolen]: True if executed, False if not executed
        """
        data = {"culture":culture}
        if user_id != None:
            url  = self.source_url+f"/odata/Users({user_id})/UiPath.Server.Configuration.OData.ChangeUserCulture"
        else:
            url  = self.source_url+f"/odata/Users/UiPath.Server.Configuration.OData.ChangeCulture"
        responce = self.post_api_call(url,data)
        if responce == 200:
            return True
        else:
            return False 
    
    def get_webhooks(self,webhook_id = None):
        """ gets workbook list or requested workbook

        Args:
            webhook_id (int, optional): id of requested workbook. Defaults to None.
        """

        if webhook_id != None:
            url  = self.source_url+f"/odata/Webhooks({webhook_id})"
        else:
            url  = self.source_url+f"/odata/Webhooks"
        responce = self.get_api_call(url)
        if responce == 200:
            return True
        else:
            return False

    def create_webhooks(self,data):
        """Create a new webhook subscription

        Args:
            data (array[arr1]):
            Url (string): stringMax. Length:2000,
            Enabled (boolean),
            Secret (string, optional): stringMax. Length:100,
            SubscribeToAllEvents (boolean),
            AllowInsecureSsl (boolean),
            Events (Array[WebhookEventDto], optional),
            
            WebhookEventDto(dic)
                Id (integer, optional): 
        Returns:
            Url (string): stringMax. Length:2000,
            Enabled (boolean),
            Secret (string, optional): stringMax. Length:100,
            SubscribeToAllEvents (boolean),
            AllowInsecureSsl (boolean),
            Events (Array[WebhookEventDto], optional),
            Id (integer, optional)
        """
        url  = self.source_url+f"/odata/Webhooks"
        responce = self.post_api_call(url,data)
        return responce

    def delete_webhooks(self,webhook_id):
        """Delete a webhook subscription

        Args:
            webhook_id (int): id of requested workbook to delete
        
        Returns:
            [boolen]: True if executed, False if not executed
        """

        url  = self.source_url+f"/odata/Webhooks({webhook_id})"
        responce = self.delete_api_call(url)
        if responce == 204:
            return True
        else:
            return False

    def get_webhooks_events(self):
        """
        Gets the list of event types a webhook can subscribe to

        Returns:
            [list[]]: 
            @odata.context (string, optional),
            value (Array[WebhookEventTypeDto], optional) 

            WebhookEventTypeDto :
            Name (string, optional): Event type key ,
            Group (string, optional): Group

        """    
        url  = self.source_url+f"/odata/Webhooks/UiPath.Server.Configuration.OData.GetEventTypes()"
        responce = self.get_api_call(url)
        return responce
     
     def get_tenents(self):
        """ Gets Tenents

        Returns:
        ODataResponse[List[TenantDto]] 
            @odata.context (string, optional),
            value (Array[TenantDto], optional)
        
        TenantDto (List)
            Name (string, optional): Name of the tenant. stringMax. Length:64Reg. Exp.:^[\p{L}][\p{L}0-9-_]+$,
            Key (string, optional): Unique Key of the tenant. ,
            DisplayName (string, optional): Display name of the the tenant stringMax. Length:128,
            AdminEmailAddress (string, optional): Default tenant's admin user account email address. stringMax. Length:256,
            AdminName (string, optional): Default tenant's admin user account name. stringMax. Length:32,
            AdminSurname (string, optional): Default tenant's admin user account surname. stringMax. Length:32,
            AdminPassword (string, optional): Default tenant's admin user account password. Only valid for create/update operations. stringMax. Length:32,
            LastLoginTime (string, optional): The last time a user logged in this tenant. ,
            IsActive (boolean, optional): Specifies if the tenant is active or not. ,
            AcceptedDomainsList (Array[string], optional): Accepted DNS list. ,
            HasConnectionString (boolean, optional): Specifies if the the tenant has a connection string defined ,
            ConnectionString (string, optional): DB connection string stringMax. Length:1024,
            License (TenantLicenseDto, optional): Licensing info. ,
            Id (integer, optional)
        
        TenantLicenseDto (Dic)
            HostLicenseId (integer, optional): The host license Id. ,
            CreationTime (string, optional): The date it was uploaded. ,
            Code (string, optional): The license code. ,
            Allowed (LicenseFields, optional): Contains the number of allowed licenses for each type ,
            Id (integer, optional)
        
        LicenseFields (dic)
            Unattended (integer, optional),
            Attended (integer, optional),
            NonProduction (integer, optional),
            Development (integer, optional),
            StudioX (integer, optional)        
        """

        url  = self.source_url+f"/odata/Tenants"
        responce = self.get_api_call(url)
        return responce

    # def create_tenent():
