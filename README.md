<img width="532" height="212" alt="ISUParser_logo3" src="https://github.com/user-attachments/assets/a81753d2-28c3-4620-9ba3-2eafd7afa2ff" />


#### Standalone application to parse and extract information in JSON format from the ISUP protocol

## Compilation
```
go build
```
### How to run
```
isup-parser <pcap_file> <isup type (itu or ansi)>
```

### Example
```
./isup-parser isup.pcap ansi
```

### Output Example
```go
=== JSON Buffer #1 (709 bytes) ===
{"timestamp":"2025-09-02T15:36:35.367026+02:00","packet_number":1,"chunk_index":1,"protocol":"m2pa","source_ip":"10.51.50.14","destination_ip":"10.39.50.197","source_port":9015,"destination_port":9015,"sctp_tsn":3507476227,"sctp_ppid":5,"m2pa":{"header":{"version":1,"message_class":11,"message_type":1,"message_length":28},"bsn":8315059,"fsn":297740,"priority":0},"mtp3":{"service_indicator":5,"network_indicator":2,"routing_label":{"dpc":166170,"opc":16125447,"signaling_link_selector":25,"pcs_dpc":{"network":2,"cluster":137,"member":26,"string":"2-137-26"},"pcs_opc":{"network":246,"cluster":14,"member":7,"string":"246-14-7"}}},"isup":{"message_type":16,"message_name":"RLC (Release Complete)","cic":33}}
=== End Buffer #1 ===

== JSON Buffer #2 (3039 bytes) ===
{"timestamp":"2025-09-02T15:36:35.367026+02:00","packet_number":1,"chunk_index":2,"protocol":"m2pa","source_ip":"10.51.50.14","destination_ip":"10.39.50.197","source_port":9015,"destination_port":9015,"sctp_tsn":3507476232,"sctp_ppid":5,"m2pa":{"header":{"version":1,"message_class":11,"message_type":1,"message_length":81},"bsn":8315059,"fsn":297745,"priority":0},"mtp3":{"service_indicator":5,"network_indicator":2,"routing_label":{"dpc":166170,"opc":141578,"signaling_link_selector":24,"pcs_dpc":{"network":2,"cluster":137,"member":26,"string":"2-137-26"},"pcs_opc":{"network":2,"cluster":41,"member":10,"string":"2-41-10"}}},"isup":{"message_type":1,"message_name":"IAM (Initial Address Message)","cic":1663,"iam":{"nature_of_connection":{"satellite":1,"satellite_name":"One Satellite circuit in connection","continuity_check":0,"continuity_check_name":"Continuity check not required","echo_device":1,"echo_device_name":"Echo control device included"},"forward_call":{"national_international_call":0,"national_international_call_name":"Call to be treated as national call","end_to_end_method":0,"end_to_end_method_name":"No End-to-end method available (only link-by-link method available)","interworking":0,"interworking_name":"no interworking encountered (No. 7 signalling all the way)","end_to_end_information":0,"end_to_end_information_name":"no end-to-end information available","isup":1,"isup_name":"ISDN user part used all the way","isup_preference":1,"isup_preference_name":"ISDN user part not required all the way","isdn_access":0,"isdn_access_name":"originating access non-ISDN","sccp_method":0,"sccp_method_name":"no indication","ported_number":1,"ported_number_name":"number not translated","query_on_release":0,"query_on_release_name":"QoR routing attempt"},"calling_party_category":{"num":10,"name":"ordinary calling subscriber"},"called_party_number":{"inn":0,"inn_name":"routing to internal network number allowed","ton":3,"ton_name":"national (significant) number","npi":1,"npi_name":"ISDN (Telephony) numbering plan (ITU-T Recommendation E.164)","num":"3322421999"},"user_service_information":{"coding_standard":"ITU-T standardized coding","information_transfer_capability":"Speech","transfer_mode":"Circuit mode","information_transfer_rate":"64 kbit/s","layer1_id":1,"user_info_layer1_protocol":"G.711 u-law"},"calling_party_number":{"ton":3,"ton_name":"national (significant) number","npi":1,"npi_name":"ISDN (Telephony) numbering plan (ITU-T Recommendation E.164)","ni":0,"ni_name":"complete","restrict":0,"restrict_name":"presentation allowed","screened":3,"screened_name":"network provided","num":"5185306460"},"hop_counter":30,"generic_number":{"nqi":192,"nqi_name":"reserved for national use","ton":3,"ton_name":"national (significant) number","ni":0,"ni_name":"complete","npi":1,"npi_name":"ISDN (Telephony) numbering plan (ITU-T Recommendation E.164)","restrict":0,"restrict_name":"presentation allowed","screened":0,"screened_name":"user provided, not verified","num":"7187626100"},"jurisdiction":"518265"}}}
=== End Buffer #2 ===

Processed 2 JSON buffers total
Processed 1 packets, successfully parsed 2 SIGTRAN messages
M2PA packets: 2, M3UA packets: 0
```


## Sponsor
[QXIP B.V.](https://qxip.net) is the main sponsor of this project, supporting open-source innovation
