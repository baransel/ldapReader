#include <iostream>
#include "ldapReader.h"

int main(int argc, char** argv)
{
    const char* serverUri="ldap://ldapserver.example.org";
    const char* user = "cn=ldapbinduser,ou=\"Example Organization Unit\",dc=example,dc=org";
    const char* pass = "Password";
    const char* filter = "(objectClass=user)";
    const char* base = "ou=SSO,dc=example,dc=org";
    
    
//example ldap read
    ldapReader *reader1;
    try
    {
        //create object and do ldap bind
        reader1 = new ldapReader(serverUri,user,pass);
        
        //make query
        reader1->query(filter,base,3,"sAMAccountName","memberOf");
    }
    catch(std::exception &e)
    {
        //if exception occur, print it to the screen and exit
        std::cerr << e.what() << std::endl;
        return -1;
    }
    
    //variable for holding attribute values
    berval **value_holder;
    
    //loop for every result
    while(reader1->fetch())
    {
        //output formatting
        std::cout << "---------------------------------------------------------" << std::endl;

        
        
        
        //single value attribute (ex: username)
    //-------------------------------------------------------
        //get attribute of the current object
        value_holder = reader1->getAttribute("sAMAccountName");
        
        //check for null
        if( value_holder != NULL && value_holder[0] != NULL)
            std::cout << value_holder[0]->bv_val;
        
        //clear memory
        ldapReader::clearBerval(value_holder);
    //-------------------------------------------------------
    
    
    
        //output formatting
        std::cout << std::endl;
        
        
        
        //multi-value attribute (ex: group membership)
    //-------------------------------------------------------
        //get attribute of the current object
        value_holder = reader1->getAttribute("memberOf");
        
        //check for null
        if( value_holder != NULL && value_holder[0] != NULL)
            for(int i=0; value_holder[i] != NULL; i++)
                std::cout << value_holder[i]->bv_val << std::endl;
        
        //clear memory
        ldapReader::clearBerval(value_holder);
    //-------------------------------------------------------    
    
    
        //output formatting
        std::cout << "---------------------------------------------------------" << std::endl;
    
        //break the loop (test purposes)
        break;
    }
    
    return 0;
}