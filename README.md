# OCI-WAF-Logging
Ingest OCI WAF Logs into the OCI Logging Service

1. To use this function, an Event rule should be created to match an object creation in the WAF log bucket.  The corresponding action should invoke the attached function.  Whenever a new log is posted to the bucket the function will automatically process the content.
 
2. There is only a single required function configuration parameter:  compartment_ocid
This should specify the target compartment for uploading content to the Logging service.  It does not have to be the same compartment as the bucket.

3. There are two optional parameters that can be added in this same configuration section:  waf-stg-log-group-name and waf-stg-log-name
The code will automatically create the Logging service Log Group and Custom Log if not present.  These are optional parameters, and if not specified along with compartment_ocid the following default values will be used as shown in the code. 

