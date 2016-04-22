		LogRhythm Security Operations
		Endpoint Lockdown SmartResponse
		greg . foss [at] logrhythm . com
		v0.1 -- June 2015

## [Summary]

This plugin adds endpoint lockdown functionality to the LogRhythm SIEM. This is a useful plugin when combined with Malware alarms, especially when there is risk that the malware will spread to a share or other critical systems within the enterprise. Sometimes the quickest and most effective way to stop the spread of malware is to simply knock the host offline until IT/Security can respond.


## [Detail]

This plugin is designed to be launched form the LogRhythm XM/EM or via standalone PowerShell. Administrative credentials should be leveraged during lockdown however it is best practice to change these credentials immediately once they have been used to access a potentially compromised host.
The script takes the following actions to effective quarantine the host until it can be retrieved by IT/Security personnel. First, all network interfaces are disabled. This is key as the network connection to the enterprise is immediately severed to prevent malware propagation. Next, the user is logged out (forced) and the system is locked.
It’s important to note that the user could still log back in and within environments where users have administrative rights, they would be able to re-enable their network interface(s). Most environments implement least-user privilege so the system would remain offline until IT/Security intervened. 


## [Environment]

This SmartResponse is designed to work with malware detection rules or similar attack activity wherein the most effective means of halting the attack is to knock the system offline. The caveat is that the alarm needs to contain either host or IP data to designate the system that will be locked down.


## [Usage]

Once the plugin is imported and chosen as the action for an alarm, you should enter the metadata for the target host, administrative username, and administrative password. Configure this as an action for Alarms where there is risk of malware outbreak or similar significant risk to the organization. Assure that approvers are assigned to execute the SmartResponse and that workflow is in place to respond to the ‘quarantined’ host.


## [License]

Copyright (c) 2016, LogRhythm
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of LogRhythm, LogRhythm Labs, nor the names of any of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

