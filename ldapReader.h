/* 
 * File         : ldapReader.h
 * Author       : B.Baransel BAĞCI
 * Description  : A c++ class for ldap read operation.
 * Compile Opt  : -lldap
 * 
 * Dependency   : 
 *                  RHEL 6
 *                      openldap-devel-2.4.39-8.el6.x86_64
 */

#ifndef LDAPREADER_H
#define	LDAPREADER_H

//for ldap functions
#include <ldap.h>
//for standart exception type
#include <stdexcept>
//for variable parameter in function query(...)
#include <cstdarg>

//default Ldap Version to 3
#define _DEFAULT_LDAP_VERSION LDAP_VERSION3
//default page size
#define _DEFAULT_PAGE_SIZE 1000
//in default paging is mandatory, if server does not support paging throw exception
#define _DEFAULT_PAGING_CRITICAL 'T'
//max number of attributes which can be retrieved in one query.
#define _DEFAULT_MAX_NUMBER_OF_ATTRIBUTES 50

/*
 * Exception class for ldap communication in this library.
 * Exceptions can be catch with the standart type " std:exception "
 */
class ldapException : public std::runtime_error
{
    public:
        /*
         * Throw an runtime_error exception in the type std:exception
         * @param @msg      char* : Error message. Example: "Auth parameters doesn't exist"
         */
        explicit ldapException(const char * msg) : std::runtime_error(msg){};
};

/*
 * General ldapReader class
 */
class ldapReader
{   
    public:
        /*
         * Define object and initialize session with server.
         * @param @serverUri    char* : Server connection uri. Example: "ldap://example.org:389"
         */
        ldapReader(const char* serverUri)
        {
            //set defaults
            this->_start();

            //set uri
            this->_setUri(serverUri);

            //call initializer
            this->_initialize();

            //set version
            this->_setVersion(_DEFAULT_LDAP_VERSION);
        };
        
        /*
         * Define object and initialize session with server.
         * @param @serverUri    char* : Server connection uri. Example: "ldap://example.org:389"
         * @param @version      unsigned int : wPrefferred LDAP Version. If null, ldap library default will be used.
         */
        ldapReader(const char* serverUri, unsigned int version)
        {
            //set defaults
            this->_start();

            //set uri
            this->_setUri(serverUri);

            //call initializer
            this->_initialize();

            //set version
            if (version != (int)NULL)
                this->_setVersion(version);
        };
        
        /*
         * Define object and initialize session with server and bind.
         * @param @serverUri    char* : Server connection uri. Example: "ldap://example.org:389"
         * @param @bindUser     char* : Full dn of bind user. Example: "cn=user1,ou=Accounts,dc=example,dc=org"
         * @param @bindPass     char* : Password of bind user. Example: "Passw0rd"
         */
        ldapReader(const char* serverUri, const char* bindUser, const char* bindPass)
        {
            //set defaults
            this->_start();

            //set uri
            this->_setUri(serverUri);

            //call initializer
            this->_initialize();

            //set version
            this->_setVersion(_DEFAULT_LDAP_VERSION);
            
            //bind
            this->bind(bindUser,bindPass);
        };
        
        /*
         * Define object and initialize session with server and bind.
         * @param @serverUri    char* : Server connection uri. Example: "ldap://example.org:389"
         * @param @bindUser     char* : Full dn of bind user. Example: "cn=user1,ou=Accounts,dc=example,dc=org"
         * @param @bindPass     char* : Password of bind user. Example: "Passw0rd"
         * @param @version      unsigned int : Prefferred LDAP Version. If null, ldap library default will be used.
         */
        ldapReader(const char* serverUri, const char* bindUser, const char* bindPass, unsigned int version)
        {
            //set defaults
            this->_start();

            //set uri
            this->_setUri(serverUri);

            //call initializer
            this->_initialize();

            //set version
            if (version != (int)NULL)
                this->_setVersion(version);
            
            //bind
            this->bind(bindUser,bindPass);
        };
        
        virtual ~ldapReader() {};
        
        /*
         * Bind to server.
         * @param @rebind       bool : Try to rebind if already binded. Example: false
         */
        void bind(bool rebind = false)
        {
            if( this->isBinded && !rebind)
                throw *(new ldapException("Already binded"));
                
            //check auth parameters set
            if( ! this->isCredExist )
                throw *(new ldapException("Auth parameters doesn't exist"));

            this->_bind();
        };
        
        /*
         * Bind to server.
         * @param @bindUser     char* : Full dn of bind user. Example: "cn=user1,ou=Accounts,dc=example,dc=org"
         * @param @bindPass     char* : Password of bind user. Example: "Passw0rd"
         * @param @rebind       bool : Try to rebind if already binded. Useful for changing bind accounta. Example: false
         */
        void bind(const char* bindUser, const char* bindPass, bool rebind = false)
        {
            if( this->isBinded && !rebind)
                throw *(new ldapException("Already binded"));
            
            //set credential
            this->_setCred(bindUser,bindPass);

            this->_bind();
        };
        
        /*
         * Set page size for query. Default is 1000
         * @param @ps       int: Page size. Example: 2000
         */
        void setPageSize(int ps)
        {
            this->pageSize = ps;
        };
        
        //FIX ME: ldap func. doesn't return count??
        /*ber_int_t getResultCount()
        {
            return this->resultCount;
        }*/
        
        /*
         * Make query for all attributes
         * @param @searchFilter     char* : Ldap search filter. Example: "(&(objectClass=user)(uidNumber=*))"
         * @param @searchBase       char* : Ldap search base. Example: "ou=users,dc=example,dc=org"
         */
        void query(const char* searchFilter, const char* searchBase)
        {
            this->query(searchFilter,searchBase,0);
        };
        
        /*
         * Make query for all attributes
         * @param @searchFilter     char* : Ldap search filter. Example: "(&(objectClass=user)(uidNumber=*))"
         * @param @searchBase       char* : Ldap search base. Example: "ou=users,dc=example,dc=org"
         * @param @attrNum          unsigned int : Number of attributes which requested. This also must be exact number of variables parameters
         * @param @attributeName ...      char* : Names of requested attributes. Each attribute is different parameter. Example: "uidNumber"
         */
        void query(const char* searchFilter, const char* searchBase, unsigned int attrNum, ...)
        {
             //allocate and set search filter
            this->searchFilter = new char[strlen(searchFilter)+1];
            memcpy(this->searchFilter,searchFilter,strlen(searchFilter)+1);
            
             //allocate and set search base
            this->searchBase = new char[strlen(searchBase)+1];
            memcpy(this->searchBase,searchBase,strlen(searchBase)+1);

            if( attrNum > 0 )
            {
                //check requested attributes number
                if( attrNum > _DEFAULT_MAX_NUMBER_OF_ATTRIBUTES)
                    throw *(new ldapException("Too many attributes requested."));

                //allocate memory for requested attribute names. +1 for NULL element
                this->requestedAttributes = new char*[attrNum+1];

                char* buf;
                va_list vp;
                va_start(vp,attrNum);
                
                //get all attribute name and set it in object
                for(int i=0; i<attrNum; i++)
                {
                    buf = va_arg(vp,char*);
                    this->requestedAttributes[i] = new char[strlen(buf)+1];
                    memcpy(this->requestedAttributes[i],buf,strlen(buf)+1);
                }
                va_end(vp);
                
                //attribute list must end with NULL, so set last element to NULL
                this->requestedAttributes[attrNum] = NULL;
            }

            //if exist, delete old result
            if( this->result != NULL )
                ldap_memfree(this->result);
            
            this->_query();
        };
        
        /*
         * Fetch next object from query result. Id here is no more object, return false.
         */
        bool fetch()
        {
            if(this->result == NULL)
                return false;
            else if( this->entry == NULL )
            {
                //set first entry
                this->entry = ldap_first_entry(this->connection,this->result);

                if( this->entry != NULL )
                    return true;
                else
                    return false;
            }
            
            this->entry = ldap_next_entry(this->connection,this->entry);
            
            if( this->entry != NULL)
                return true;
            
            if( this->isMorePageAvailable )
            {
                this->_query();
                return this->fetch();
            }
            else
                return false;
            
        }
        
        /*
         * Get attribute value from current object.
         * @return berval** : Return multiple values in struct berval array
         * @param @attributeName    char* : Atrribute name. Example: "uidNumber"
         */
        struct berval** getAttribute(char* attributeName)
        {
            struct berval **ret;
            
            if(this->entry == NULL)
                throw *(new ldapException("No entry retrieved from server"));
            
            ret = ldap_get_values_len(this->connection, this->entry, attributeName);
            
            return ret;
            
        }
        
        /*
         * Clear attribute value result from memory
         * @param @ptr      berval** : Pointer array to berval* 
         */
        static void clearBerval(berval** ptr)
        {
            if(ptr != NULL)
            {
                for(int i=0; ptr[i] != NULL; i++)
                    ber_bvfree(ptr[i]);
                delete [] ptr;
            }
        }
        
    private:
        //set default variables
        void _start()
        {
            this->isBinded = false;
            this->isInitialized = false;
            this->isCredExist= false;
            this->bindCred.bv_len = 0;
            this->bindCred.bv_val = NULL;
            this->version = 0;
            this->searchBase = NULL;
            this->searchFilter = NULL;
            this->requestedAttributes = NULL;
            this->pageSize = _DEFAULT_PAGE_SIZE;
            this->isPagingCritical = _DEFAULT_PAGING_CRITICAL;
            this->pageControl = NULL;
            this->result = NULL;
            this->isMorePageAvailable = false;
            this->entry = NULL;
            this->controls = NULL;
            this->resultCount = 0;
        };
        
        //set uri
        void _setUri(const char* serverUri)
        {
            //allocate uri for "ldap://server\n"
            this->uri = new char[strlen(serverUri)+1];
            memcpy(this->uri, serverUri, strlen(serverUri)+1);
        };
        
        //set cred
        void _setCred(const char* bindUser, const char* bindPass)
        {
            //free old credential
            if( this->isCredExist )
            {
                delete[] this->bindUser;
                delete[] this->bindCred.bv_val;
                this->bindCred.bv_len = 0;
            }

            //allocate and set username
            this->bindUser = new char[strlen(bindUser)+1];
            memcpy(this->bindUser,bindUser,strlen(bindUser)+1);

            //allocate and set password
            this->bindCred.bv_len = strlen(bindPass);
            this->bindCred.bv_val = new char[this->bindCred.bv_len +1];
            memcpy(this->bindCred.bv_val,bindPass,this->bindCred.bv_len +1);

            //set auth control true
            this->isCredExist = true;
        };
        
        //initialize
        void _initialize()
        {
            int ret = ldap_initialize(&this->connection,this->uri);

            if( ret != LDAP_SUCCESS)
                throw *(new ldapException(ldap_err2string(ret)));

            this->isInitialized = true;
        };
        
        //set ldap version
        void _setVersion(unsigned int v)
        {
            this->version = v;

            int ret = ldap_set_option(this->connection, LDAP_OPT_PROTOCOL_VERSION,&this->version);

            if( ret != LDAP_SUCCESS)
                throw *(new ldapException(ldap_err2string(ret)));
        };
        
        //bind
        void _bind()
        {
            int ret = ldap_sasl_bind_s(this->connection, this->bindUser, NULL, &this->bindCred , NULL, NULL, &this->servcred );

            if( ret != LDAP_SUCCESS)
                throw *(new ldapException(ldap_err2string(ret)));

            this->isBinded = true;
        };
        
        //prepare page control
        void _preparePageControl()
        {
            if(this->pageControl != NULL)
            {
                ldap_control_free(this->pageControl);
                this->pageControl = NULL;
            }
            
            int ret = ldap_create_page_control(this->connection, this->pageSize, &this->pageCookie, this->isPagingCritical, &this->pageControl );
            
            if( ret != 0)
                throw *(new ldapException(ldap_err2string(ret)));

        };
        
        void _prepareControls()
        {
            //allocate controls
            //there is only one control so far, but we cannot allocate 1 item array. make it 2 and left null
            if( this->controls == NULL)
                this->controls = new LDAPControl*[2];
            
            //prepare page control variables
            this->_preparePageControl();
            
            this->controls[0] = this->pageControl;
            this->controls[1] = NULL;
        }
        
        void _query()
        {
            //for return value of ldap functions
            int ret;
            
            //prepare page control
            this->_prepareControls();
            
            //do the search
            ret = ldap_search_ext_s(this->connection, this->searchBase, LDAP_SCOPE_SUBTREE, this->searchFilter, this->requestedAttributes, 0, this->controls, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &this->result);
            //ret = ldap_search_ext_s(this->connection, this->searchBase, LDAP_SCOPE_SUBTREE, this->searchFilter, NULL, 0, this->controls, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &this->result);
            if( ret != LDAP_SUCCESS)
                throw *(new ldapException(ldap_err2string(ret)));
            
            int tmp_err;
            LDAPControl **returnedControls;
            
            ret = ldap_parse_result(this->connection,this->result,&tmp_err,NULL,NULL,NULL,&returnedControls,false);
            if( ret != LDAP_SUCCESS)
                throw *(new ldapException(ldap_err2string(ret)));
            
            ret = ldap_parse_pageresponse_control(this->connection, returnedControls[0], &this->resultCount, &this->pageCookie);
            if( ret != LDAP_SUCCESS)
                throw *(new ldapException(ldap_err2string(ret)));
            
            if (returnedControls != NULL)
            {
                ldap_controls_free(returnedControls);
                returnedControls = NULL;
            }
            
            //check if there is more page
            if(this->pageCookie.bv_val != NULL && (strlen(this->pageCookie.bv_val) > 0))
                this->isMorePageAvailable = true;
            else
                this->isMorePageAvailable = false;
        }
        
        //ldap connection holder
        LDAP * connection;
        
        //ldap uri
        char * uri;
        
        //ldap version
        unsigned int version;
        
        //ldap auth user
        char * bindUser;
        
        //ldap auth cred
        struct berval bindCred;
        
        //server cred
        struct berval *servcred; 
        
        //ldap search base
        char* searchBase;

        //ldap filter
        char* searchFilter;
        
        //ldap attribute
        char** requestedAttributes;
        
        //ldap page size
        int pageSize;
        
        //ldap paging cookie
        struct berval pageCookie;
        //ldap page control variable
        LDAPControl* pageControl;
        
        //ldap general control array
        LDAPControl** controls;
        
        //ldap result holder
        LDAPMessage* result;
        LDAPMessage* entry;
        
        ber_int_t resultCount;
        
        //is paging critical? T or F
        char isPagingCritical;
        bool isInitialized;
        bool isBinded;
        bool isCredExist;
        bool isMorePageAvailable;
        
};

#endif	/* LDAPREADER_H */