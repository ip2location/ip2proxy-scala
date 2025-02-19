# IP2Proxy Scala Library

This library allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy

As an alternative, this library can also call the IP2Proxy Web Service. This requires an API key. If you don't have an existing API key, you can subscribe for one at the below:

https://www.ip2location.com/web-service/ip2proxy

## Requirements ##
Intellij IDEA: https://www.jetbrains.com/idea/

## QUERY USING THE BIN FILE

## Methods
Below are the methods supported in this library.

|Method Name|Description|
|---|---|
|Open|Open the IP2Proxy BIN data for lookup. Please see the **Usage** section of the 2 modes supported to load the BIN data file.|
|Close|Close and clean up the file pointer.|
|GetPackageVersion|Get the package version (1 to 12 for PX1 to PX12 respectively).|
|GetModuleVersion|Get the module version.|
|GetDatabaseVersion|Get the database version.|
|IsProxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|GetAll|Return the proxy information in an object.|
|GetProxyType|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of proxy types supported|
|GetCountryShort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|GetCountryLong|Return the ISO3166-1 country name of the proxy.|
|GetRegion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported|
|GetCity|Return the city name of the proxy.|
|GetISP|Return the ISP name of the proxy.|
|GetDomain|Return the domain name of the proxy.|
|GetUsageType|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of usage types supported.|
|GetASN|Return the autonomous system number of the proxy.|
|GetAS|Return the autonomous system name of the proxy.|
|GetLastSeen|Return the number of days that the proxy was last seen.|
|GetThreat|Return the threat type of the proxy.|
|GetProvider|Return the provider of the proxy.|
|getFraudScore|Return the potential risk score (0 - 99) associated with IP address.|

## Usage

Open and read IP2Proxy binary database. There are 2 modes:

1. **IOModes.IP2PROXY_FILE_IO** - File I/O reading. Slower lookup, but low resource consuming. This is the default.
2. **IOModes.IP2PROXY_MEMORY_MAPPED** - Stores whole IP2Proxy database into a memory-mapped file. Extremely resources consuming. Do not use this mode if your system do not have enough memory.

```scala
object IP2ProxyTest {
  def main(args: Array[String]): Unit = {
    try {
      val Proxy = new IP2Proxy
      var All: ProxyResult = null
      var IsProxy: Int = 0
      var ProxyType: String = null
      var CountryShort: String = null
      var CountryLong: String = null
      var Region: String = null
      var City: String = null
      var ISP: String = null
      var Domain: String = null
      var UsageType: String = null
      var ASN: String = null
      var AS: String = null
      var LastSeen: String = null
      var Threat: String = null
      var Provider: String = null
      val IP = "221.121.146.0"
      if (Proxy.Open("./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN", IP2Proxy.IOModes.IP2PROXY_MEMORY_MAPPED) == 0) {
        System.out.println("GetModuleVersion: " + Proxy.GetModuleVersion)
        System.out.println("GetPackageVersion: " + Proxy.GetPackageVersion)
        System.out.println("GetDatabaseVersion: " + Proxy.GetDatabaseVersion)

        // reading all available fields
        All = Proxy.GetAll(IP)
        System.out.println("Is_Proxy: " + String.valueOf(All.Is_Proxy))
        System.out.println("Proxy_Type: " + All.Proxy_Type)
        System.out.println("Country_Short: " + All.Country_Short)
        System.out.println("Country_Long: " + All.Country_Long)
        System.out.println("Region: " + All.Region)
        System.out.println("City: " + All.City)
        System.out.println("ISP: " + All.ISP)
        System.out.println("Domain: " + All.Domain)
        System.out.println("Usage_Type: " + All.Usage_Type)
        System.out.println("ASN: " + All.ASN)
        System.out.println("AS: " + All.AS)
        System.out.println("Last_Seen: " + All.Last_Seen)
        System.out.println("Threat: " + All.Threat)
        System.out.println("Provider: " + All.Provider)

        // reading individual fields
        IsProxy = Proxy.IsProxy(IP)
        System.out.println("Is_Proxy: " + String.valueOf(IsProxy))
        ProxyType = Proxy.GetProxyType(IP)
        System.out.println("Proxy_Type: " + ProxyType)
        CountryShort = Proxy.GetCountryShort(IP)
        System.out.println("Country_Short: " + CountryShort)
        CountryLong = Proxy.GetCountryLong(IP)
        System.out.println("Country_Long: " + CountryLong)
        Region = Proxy.GetRegion(IP)
        System.out.println("Region: " + Region)
        City = Proxy.GetCity(IP)
        System.out.println("City: " + City)
        ISP = Proxy.GetISP(IP)
        System.out.println("ISP: " + ISP)
        Domain = Proxy.GetDomain(IP)
        System.out.println("Domain: " + Domain)
        UsageType = Proxy.GetUsageType(IP)
        System.out.println("UsageType: " + UsageType)
        ASN = Proxy.GetASN(IP)
        System.out.println("ASN: " + ASN)
        AS = Proxy.GetAS(IP)
        System.out.println("AS: " + AS)
        LastSeen = Proxy.GetLastSeen(IP)
        System.out.println("LastSeen: " + LastSeen)
        Threat = Proxy.GetThreat(IP)
        System.out.println("Threat: " + Threat)
        Provider = Proxy.GetProvider(IP)
        System.out.println("Provider: " + Provider)
      }
      else System.out.println("Error reading BIN file.")
      Proxy.Close
    } catch {
      case ex: Exception =>
        System.out.println(ex)
    }
  }
}
```

## QUERY USING THE IP2PROXY PROXY DETECTION WEB SERVICE

## Methods
Below are the methods supported in this library.

|Method Name|Description|
|---|---|
|Open| Expects 3 input parameters:<ol><li>IP2Proxy API Key.</li><li>Package (PX1 - PX11)</li></li><li>Use HTTPS or HTTP</li></ol> |
|IPQuery|Query IP address. This method returns a JsonObject containing the proxy info. <ul><li>countryCode</li><li>countryName</li><li>regionName</li><li>cityName</li><li>isp</li><li>domain</li><li>usageType</li><li>asn</li><li>as</li><li>lastSeen</li><li>threat</li><li>proxyType</li><li>isProxy</li><li>provider</li><ul>|
|GetCredit|This method returns the web service credit balance in a JsonObject.|

## Usage

```scala
object IP2ProxyTest {
  def main(args: Array[String]): Unit = {
    try {
      val ws = new IP2ProxyWebService
      val strIPAddress = "8.8.8.8"
      val strAPIKey = "YOUR_API_KEY"
      val strPackage = "PX11"
      val boolSSL = true
      ws.Open(strAPIKey, strPackage, boolSSL)
      var myResult = ws.IPQuery(strIPAddress)
      if (myResult.get("response") != null && myResult.get("response").getAsString == "OK") {
        System.out.println("countryCode: " + (if (myResult.get("countryCode") != null) myResult.get("countryCode").getAsString
        else ""))
        System.out.println("countryName: " + (if (myResult.get("countryName") != null) myResult.get("countryName").getAsString
        else ""))
        System.out.println("regionName: " + (if (myResult.get("regionName") != null) myResult.get("regionName").getAsString
        else ""))
        System.out.println("cityName: " + (if (myResult.get("cityName") != null) myResult.get("cityName").getAsString
        else ""))
        System.out.println("isp: " + (if (myResult.get("isp") != null) myResult.get("isp").getAsString
        else ""))
        System.out.println("domain: " + (if (myResult.get("domain") != null) myResult.get("domain").getAsString
        else ""))
        System.out.println("usageType: " + (if (myResult.get("usageType") != null) myResult.get("usageType").getAsString
        else ""))
        System.out.println("asn: " + (if (myResult.get("asn") != null) myResult.get("asn").getAsString
        else ""))
        System.out.println("as: " + (if (myResult.get("as") != null) myResult.get("as").getAsString
        else ""))
        System.out.println("lastSeen: " + (if (myResult.get("lastSeen") != null) myResult.get("lastSeen").getAsString
        else ""))
        System.out.println("proxyType: " + (if (myResult.get("proxyType") != null) myResult.get("proxyType").getAsString
        else ""))
        System.out.println("threat: " + (if (myResult.get("threat") != null) myResult.get("threat").getAsString
        else ""))
        System.out.println("isProxy: " + (if (myResult.get("isProxy") != null) myResult.get("isProxy").getAsString
        else ""))
        System.out.println("provider: " + (if (myResult.get("provider") != null) myResult.get("provider").getAsString
        else ""))
      }
      else if (myResult.get("response") != null) System.out.println("Error: " + myResult.get("response").getAsString)
      myResult = ws.GetCredit
      if (myResult.get("response") != null) System.out.println("Credit balance: " + myResult.get("response").getAsString)
    } catch {
      case e: Exception =>
        System.out.println(e)
        e.printStackTrace(System.out)
    }
  }
}

```