---
title: System Center 2016 - Operations Manager Release Build Versions
description: Include file that shows the list of release builds for System Center 2016 - Operations Manager.
author: Jeronika-MS
ms.author: v-gajeronika
ms.date: 10/02/2024
ms.update-cycle: 1095-days
ms.service: system-center
ms.assetid:
ms.subservice: operations-manager
ms.topic: include
---

## Operations Manager 2016 build versions

>[!NOTE]
>All System Center Operations Manager update rollups are cumulative. This means you don't need to apply them in order; you can always apply the latest update. If you've deployed System Center 2016 - Operations Manager and never applied an update rollup, you can proceed to install the latest one available.

The following tables list the release history for Operations Manager 2016.

### Management Server (and other components*)
|Build Number |KB |Release Date |Description |
|-------------|---|-------------|------------|
|7.2.11719.0 ||September 2016 |General Availability release|  
|7.2.11759.0 |[3190029](https://support.microsoft.com/kb/3190029) |October 2016 |Update Rollup 1 |  
|7.2.11822.0 |[3209591](https://support.microsoft.com/kb/3209591) |February 2017 |Update Rollup 2 |  

### Agent and Gateway
|Build Number |KB |Release Date |Description |
|-------------|---|-------------|------------|
|8.0.10918.0 ||September 2016 |General Availability release|  
|8.0.10931.0 |[3190029](https://support.microsoft.com/kb/3190029) |October 2016 |Update Rollup 1 |  
|8.0.10949.0 |[3209591](https://support.microsoft.com/kb/3209591) |February 2017 |Update Rollup 2 |  

### SCX Agent
|Build Number |KB |Release Date |Agent Version |Description |
|-------------|---|-------------|--------------|------------|
|7.6.1064.0 ||September 2016 |1.6.2-336 |General Availability release|  
|7.6.1067.0 ||October 2016 |1.6.2-337 |Update Rollup 1 |  
|7.6.1072.0 ||February 2017 |1.6.2-338 |Update Rollup 2 |  

 \* *The other components include: Databases, Operations Consoles, Reporting, and Web Consoles.*

 <sup>1</sup> *All System Center Operations Manager update rollups are cumulative. This means you don't need to apply them in order; you can always apply the latest update. However, there's one exception to this upgrade behavior. If you want the ability to uninstall UR4, you should ensure you've previously applied UR2 or UR3, which fixed an uninstall issue. Update rollups subsequent to UR4 can be uninstalled without previous rollups being applied.*
