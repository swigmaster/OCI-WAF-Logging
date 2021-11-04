#
# waf-logs-upload version 1.0
#
# Copyright (c) 2021 Oracle, Inc.  All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
#

import io
import json
import oci
from datetime import datetime
import gzip
import uuid
import logging

from fdk import response

"""
Check if Logging service Log Group exists; create if not present
"""
def prepLogGroup(_logging_client, _compartment_id, _logGrpName, _logger):
    try:
        list_log_groups_response = _logging_client.list_log_groups(
            compartment_id=_compartment_id,
            display_name=_logGrpName)
        if (list_log_groups_response.data):
            return list_log_groups_response.data[0].id
        else:
            _logger.info("Creating log group: {}".format(_logGrpName))
            create_log_group_response = _logging_client.create_log_group(
                create_log_group_details=oci.logging.models.CreateLogGroupDetails(
                    compartment_id=_compartment_id,
                    display_name=_logGrpName,
                    description="Log group for ingesting WAF stage logs"
                )
            )
            list_log_groups_response = _logging_client.list_log_groups(
                compartment_id=_compartment_id,
                display_name=_logGrpName)
            if (list_log_groups_response.data):
                return list_log_groups_response.data[0].id
    except Exception as err:
        _logger.error("An exception occured in prepLogGroup(): {}".format(str(err)))
        raise(err)


"""
Check if Logging service custom Log exists; create if not present
"""
def prepWafStageLog(_logging_client, _logGrpOCID, _logName, _logger):
    try:
        list_logs_response = _logging_client.list_logs(
            log_group_id=_logGrpOCID,
            log_type="CUSTOM",
            display_name=_logName)
        if (list_logs_response.data):
            return list_logs_response.data[0].id
        else:
            _logger.info("Creating WAF stage log: {}".format(_logName))
            create_log_response = _logging_client.create_log(
                log_group_id=_logGrpOCID,
                create_log_details=oci.logging.models.CreateLogDetails(
                    display_name=_logName,
                    log_type="CUSTOM")
            )
            list_logs_response = _logging_client.list_logs(
                log_group_id=_logGrpOCID,
                log_type="CUSTOM",
                display_name=_logName)
            if (list_logs_response.data):
                return list_logs_response.data[0].id
    except Exception as err:
        _logger.error("An exception occured in prepWafStageLog(): {}".format(str(err))) 
        raise(err)

"""
Pull WAF log from Object Storage, decompress, parse, upload contents to Logging service
"""
def load_waf_data(_object_storage_client, _namespace, _bucket_name, _loggingingestion_client, _logOCID, _object_name, _logger):
    try:   
        get_obj = _object_storage_client.get_object(
            namespace_name=_namespace,
            bucket_name=_bucket_name,
            object_name=_object_name
        )

        if get_obj.status == 200:
            compressed_data_raw = b''
            for chunk in get_obj.data.raw.stream(1024 * 1024, decode_content=False):
                compressed_data_raw += chunk

            decompressed_byte_data = gzip.decompress(compressed_data_raw).decode()
            log_entries_list = decompressed_byte_data.splitlines()           
            length_of_list = len(log_entries_list)
            _logger.info("Number of log entries: {}".format(str(length_of_list))) 

            _log_entries = []

            for i in range(length_of_list):
                log_entry_json = json.loads(log_entries_list[i])
                log_entry = {
                    "data" :  json.dumps(log_entry_json).replace("{","").replace("}","").replace("\\","").replace('"',""),
                    "id" : str(uuid.uuid1()),
                    # Test data is from Feb/March '21, which is too old to properly ingest using original log entry timestamp.
                    # When processing recent WAF data uncomment the following line to use actual log entry timestamp.
                    #"time" : log_entry_json['@timestamp']

                    # When processing recent WAF data remove the following code line
                    "time" : datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
                }
                _log_entries.append(log_entry)

            logEntryBatches = []

            logEntryBatch = oci.loggingingestion.models.LogEntryBatch(
                entries=_log_entries,
                source="WAF-Log-Upload",
                type="WAF-Log",
                defaultlogentrytime=datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z",
                subject="WAF-Log_Staging_Area"
            ) 

            logEntryBatches.append(logEntryBatch)

            put_log_response = _loggingingestion_client.put_logs(
                log_id=_logOCID,
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    log_entry_batches=logEntryBatches,
                    specversion="1.0"
                )   
            ) 
    except Exception as err: 
        _logger.error("There was an exception in executing load_waf_data(): {}".format(str(err))) 
        raise(err) 

"""
Entrypoint and initialization
"""
def handler(ctx, data: io.BytesIO=None):
    logger = logging.getLogger()
    signer = oci.auth.signers.get_resource_principals_signer()
    object_name = bucket_name = namespace = ""

    try:
        cfg = ctx.Config()

        _compartment_id  = cfg["compartment_ocid"]

        try:
            _logGrpName  = cfg["waf-stg-log-group-name"]
        except:
            logger.info('Optional configuration key logGrpName unavailable.  Will assign default value')
            _logGrpName = "waf-stg-log-group"

        try:
            _logName  = cfg["waf-stg-log-name"]
        except:
            logger.info('Optional configuration key logName unavailable.  Will assign default value')
            _logName = "waf-stg-log"        

    except Exception as err:
        logger.error("Missing function configuration parameters: {}".format(str(err)))
        raise
    try:
        body = json.loads(data.getvalue())
        
        logger.info("Object name: " + body["data"]["resourceName"])
        object_name = body["data"]["resourceName"]
        
        logger.info("Bucket name: " + body["data"]["additionalDetails"]["bucketName"])
        bucket_name = body["data"]["additionalDetails"]["bucketName"]
        
        logger.info("Namespace: " + body["data"]["additionalDetails"]["namespace"])
        namespace = body["data"]["additionalDetails"]["namespace"]
    except Exception as err:
        logger.error("Error in initialize process: {}".format(str(err)))
        raise

    try:
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        logging_client = oci.logging.LoggingManagementClient(config={}, signer=signer)
        loggingingestion_client = oci.loggingingestion.LoggingClient(config={}, signer=signer)
        
        logGrpOCID = prepLogGroup(logging_client, _compartment_id, _logGrpName, logger)
        logOCID = prepWafStageLog(logging_client, logGrpOCID, _logName, logger)

        load_waf_data(object_storage_client, namespace, bucket_name, loggingingestion_client, logOCID, object_name, logger)        
    except Exception as err:
        logger.error("Error in main process: {}".format(str(err)))

    return response.Response(
        ctx, 
        response_data=json.dumps({"status": "Success"}),
        headers={"Content-Type": "application/json"}
    )