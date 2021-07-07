package com.ip2proxy

import java.net.{Inet4Address, Inet6Address, InetAddress, UnknownHostException}
import java.io._
import java.util.regex._
import java.math.BigInteger
import java.nio.{ByteBuffer, ByteOrder, MappedByteBuffer}
import java.nio.channels.FileChannel

object IP2Proxy {
  private val Pattern1 = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") // IPv4
  private val Pattern2 = Pattern.compile("^([0-9A-F]{1,4}:){6}(0[0-9]+\\.|.*?\\.0[0-9]+).*$", Pattern.CASE_INSENSITIVE)
  private val Pattern3 = Pattern.compile("^[0-9]+$")
  private val Pattern4 = Pattern.compile("^(.*:)(([0-9]+\\.){3}[0-9]+)$")
  private val Pattern5 = Pattern.compile("^.*((:[0-9A-F]{1,4}){2})$")
  private val Pattern6 = Pattern.compile("^[0:]+((:[0-9A-F]{1,4}){1,2})$", Pattern.CASE_INSENSITIVE)
  private val Pattern7 = Pattern.compile("^([0-9]+\\.){1,2}[0-9]+$")
  private val MAX_IPV4_RANGE = new BigInteger("4294967295")
  private val MAX_IPV6_RANGE = new BigInteger("340282366920938463463374607431768211455")
  private val FROM_6TO4 = new BigInteger("42545680458834377588178886921629466624")
  private val TO_6TO4 = new BigInteger("42550872755692912415807417417958686719")
  private val FROM_TEREDO = new BigInteger("42540488161975842760550356425300246528")
  private val TO_TEREDO = new BigInteger("42540488241204005274814694018844196863")
  private val LAST_32BITS = new BigInteger("4294967295")
  private val MSG_NOT_SUPPORTED = "NOT SUPPORTED"
  private val MSG_INVALID_IP = "INVALID IP ADDRESS"
  private val MSG_MISSING_FILE = "MISSING FILE"
  private val MSG_IPV6_UNSUPPORTED = "IPV6 ADDRESS MISSING IN IPV4 BIN"

  object IOModes extends Enumeration {
    type IOMode = Value
    val IP2PROXY_FILE_IO, IP2PROXY_MEMORY_MAPPED = Value
  }

  private object Modes extends Enumeration {
    type Mode = Value
    val COUNTRY_SHORT, COUNTRY_LONG, REGION, CITY, ISP, PROXY_TYPE, IS_PROXY, DOMAIN, USAGE_TYPE, ASN, AS, LAST_SEEN, THREAT, PROVIDER, ALL = Value
  }

  private val COUNTRY_POSITION = Array(0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3)
  private val REGION_POSITION = Array(0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4)
  private val CITY_POSITION = Array(0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5)
  private val ISP_POSITION = Array(0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6)
  private val PROXYTYPE_POSITION = Array(0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2)
  private val DOMAIN_POSITION = Array(0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7)
  private val USAGETYPE_POSITION = Array(0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8)
  private val ASN_POSITION = Array(0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9)
  private val AS_POSITION = Array(0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10)
  private val LASTSEEN_POSITION = Array(0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11, 11)
  private val THREAT_POSITION = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12)
  private val PROVIDER_POSITION = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13)
  private val _ModuleVersion = "3.1.0"
}

class IP2Proxy() {
  private var _IPv4Buffer: MappedByteBuffer = _
  private var _IPv6Buffer: MappedByteBuffer = _
  private var _MapDataBuffer: MappedByteBuffer = _
  private val _IndexArrayIPv4 = Array.ofDim[Int](65536, 2)
  private val _IndexArrayIPv6 = Array.ofDim[Int](65536, 2)
  private var _IPv4Offset: Long = _
  private var _IPv6Offset: Long = _
  private var _MapDataOffset: Long = _
  private var _IPv4ColumnSize: Int = _
  private var _IPv6ColumnSize: Int = _
  private var _BaseAddr = 0
  private var _DBCount = 0
  private var _DBColumn = 0
  private var _DBType = 0
  private var _DBDay = 1
  private var _DBMonth = 1
  private var _DBYear = 1
  private var _BaseAddrIPv6 = 0
  private var _DBCountIPv6 = 0
  private var _IndexBaseAddr = 0
  private var _IndexBaseAddrIPv6 = 0
  private var _ProductCode = 0
  // private var _ProductType = 0
  // private var _FileSize = 0
  private var _UseMemoryMappedFile = false
  private var _IPDatabasePath = ""
  private var COUNTRY_POSITION_OFFSET = 0
  private var REGION_POSITION_OFFSET = 0
  private var CITY_POSITION_OFFSET = 0
  private var ISP_POSITION_OFFSET = 0
  private var PROXYTYPE_POSITION_OFFSET = 0
  private var DOMAIN_POSITION_OFFSET = 0
  private var USAGETYPE_POSITION_OFFSET = 0
  private var ASN_POSITION_OFFSET = 0
  private var AS_POSITION_OFFSET = 0
  private var LASTSEEN_POSITION_OFFSET = 0
  private var THREAT_POSITION_OFFSET = 0
  private var PROVIDER_POSITION_OFFSET = 0
  private var COUNTRY_ENABLED = false
  private var REGION_ENABLED = false
  private var CITY_ENABLED = false
  private var ISP_ENABLED = false
  private var PROXYTYPE_ENABLED = false
  private var DOMAIN_ENABLED = false
  private var USAGETYPE_ENABLED = false
  private var ASN_ENABLED = false
  private var AS_ENABLED = false
  private var LASTSEEN_ENABLED = false
  private var THREAT_ENABLED = false
  private var PROVIDER_ENABLED = false

  /**
   * This function returns the module version.
   *
   * @return Module version
   */
  def GetModuleVersion: String = IP2Proxy._ModuleVersion

  /**
   * This function returns the package version.
   *
   * @return Package version
   */
  def GetPackageVersion: String = String.valueOf(_DBType)

  /**
   * This function returns the IP database version.
   *
   * @return IP database version
   */
  def GetDatabaseVersion: String = if (_DBYear == 0) ""
  else "20" + String.valueOf(_DBYear) + "." + String.valueOf(_DBMonth) + "." + String.valueOf(_DBDay)

  /**
   * This function returns ans integer to state if it proxy.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return -1 if error, 0 if not a proxy, 1 if proxy except DCH and SES, 2 if proxy and either DCH or SES
   */
  @throws[IOException]
  def IsProxy(IP: String): Int = ProxyQuery(IP, IP2Proxy.Modes.IS_PROXY).Is_Proxy

  /**
   * This function returns the country code.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Country code
   */
  @throws[IOException]
  def GetCountryShort(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.COUNTRY_SHORT).Country_Short

  /**
   * This function returns the country name.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Country name
   */
  @throws[IOException]
  def GetCountryLong(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.COUNTRY_LONG).Country_Long

  /**
   * This function returns the region name.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Region name
   */
  @throws[IOException]
  def GetRegion(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.REGION).Region

  /**
   * This function returns the city name.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return City name
   */
  @throws[IOException]
  def GetCity(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.CITY).City

  /**
   * This function returns the ISP name.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return ISP name
   */
  @throws[IOException]
  def GetISP(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.ISP).ISP

  /**
   * This function returns the proxy type.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Proxy type
   */
  @throws[IOException]
  def GetProxyType(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.PROXY_TYPE).Proxy_Type

  /**
   * This function returns the domain.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Domain
   */
  @throws[IOException]
  def GetDomain(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.DOMAIN).Domain

  /**
   * This function returns the usage type.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Proxy type
   */
  @throws[IOException]
  def GetUsageType(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.USAGE_TYPE).Usage_Type

  /**
   * This function returns the Autonomous System Number.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Autonomous System Number
   */
  @throws[IOException]
  def GetASN(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.ASN).ASN

  /**
   * This function returns the Autonomous System name.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Autonomous System name
   */
  @throws[IOException]
  def GetAS(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.AS).AS

  /**
   * This function returns number of days the proxy was last seen.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Number of days last seen
   */
  @throws[IOException]
  def GetLastSeen(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.LAST_SEEN).Last_Seen

  /**
   * This function returns the threat type of the proxy.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Threat type of the proxy
   */
  @throws[IOException]
  def GetThreat(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.THREAT).Threat

  /**
   * This function returns the provider of the proxy.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Provider of the proxy
   */
  @throws[IOException]
  def GetProvider(IP: String): String = ProxyQuery(IP, IP2Proxy.Modes.PROVIDER).Provider

  /**
   * This function returns proxy result.
   *
   * @param IP IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return Proxy result
   */
  @throws[IOException]
  def GetAll(IP: String): ProxyResult = ProxyQuery(IP)

  /**
   * This function destroys the mapped bytes.
   *
   * @return 0 to indicate no errors
   */
  def Close: Int = {
    DestroyMappedBytes()
    _BaseAddr = 0
    _DBCount = 0
    _DBColumn = 0
    _DBType = 0
    _DBDay = 1
    _DBMonth = 1
    _DBYear = 1
    _BaseAddrIPv6 = 0
    _DBCountIPv6 = 0
    _IndexBaseAddr = 0
    _IndexBaseAddrIPv6 = 0
    _ProductCode = 0
    // _ProductType = 0
    // _FileSize = 0
    0
  }

  private def DestroyMappedBytes(): Unit = {
    _IPv4Buffer = null
    _IPv6Buffer = null
    _MapDataBuffer = null
  }

  @throws[IOException]
  private def CreateMappedBytes(): Unit = {
    var RF: RandomAccessFile = null
    try {
      RF = new RandomAccessFile(_IPDatabasePath, "r")
      val InChannel = RF.getChannel
      CreateMappedBytes(InChannel)
    } finally if (RF != null) RF.close()
  }

  @throws[IOException]
  private def CreateMappedBytes(InChannel: FileChannel): Unit = {
    if (_IPv4Buffer == null) {
      val _IPv4Bytes = _IPv4ColumnSize.toLong * _DBCount.toLong
      _IPv4Offset = _BaseAddr - 1
      _IPv4Buffer = InChannel.map(FileChannel.MapMode.READ_ONLY, _IPv4Offset, _IPv4Bytes)
      _IPv4Buffer.order(ByteOrder.LITTLE_ENDIAN)
      _MapDataOffset = _IPv4Offset + _IPv4Bytes
    }
    if (_DBCountIPv6 > 0 && _IPv6Buffer == null) {
      val _IPv6Bytes = _IPv6ColumnSize.toLong * _DBCountIPv6.toLong
      _IPv6Offset = _BaseAddrIPv6 - 1
      _IPv6Buffer = InChannel.map(FileChannel.MapMode.READ_ONLY, _IPv6Offset, _IPv6Bytes)
      _IPv6Buffer.order(ByteOrder.LITTLE_ENDIAN)
      _MapDataOffset = _IPv6Offset + _IPv6Bytes
    }
    if (_MapDataBuffer == null) {
      _MapDataBuffer = InChannel.map(FileChannel.MapMode.READ_ONLY, _MapDataOffset, InChannel.size - _MapDataOffset)
      _MapDataBuffer.order(ByteOrder.LITTLE_ENDIAN)
    }
  }

  @throws[IOException]
  private def LoadBIN: Boolean = {
    var LoadOK = false
    var RF: RandomAccessFile = null
    try if (_IPDatabasePath.nonEmpty) {
      RF = new RandomAccessFile(_IPDatabasePath, "r")
      val InChannel = RF.getChannel
      val _HeaderBuffer = InChannel.map(FileChannel.MapMode.READ_ONLY, 0, 64) // 64 bytes header
      _HeaderBuffer.order(ByteOrder.LITTLE_ENDIAN)
      _DBType = _HeaderBuffer.get(0)
      _DBColumn = _HeaderBuffer.get(1)
      _DBYear = _HeaderBuffer.get(2)
      _DBMonth = _HeaderBuffer.get(3)
      _DBDay = _HeaderBuffer.get(4)
      _DBCount = _HeaderBuffer.getInt(5) // 4 bytes
      _BaseAddr = _HeaderBuffer.getInt(9)
      _DBCountIPv6 = _HeaderBuffer.getInt(13)
      _BaseAddrIPv6 = _HeaderBuffer.getInt(17)
      _IndexBaseAddr = _HeaderBuffer.getInt(21) //4 bytes
      _IndexBaseAddrIPv6 = _HeaderBuffer.getInt(25)
      _ProductCode = _HeaderBuffer.get(29)
      // _ProductType = _HeaderBuffer.get(30)
      // _FileSize = _HeaderBuffer.getInt(31)

      // check if is correct BIN (should be 2 for IP2Proxy BIN file), also checking for zipped file (PK being the first 2 chars)
      if (((_ProductCode != 2) && (_DBYear >= 21)) || ((_DBType == 80) && (_DBColumn == 75))) { // only BINs from Jan 2021 onwards have this byte set
        throw new IOException("Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file.")
      }

      _IPv4ColumnSize = _DBColumn << 2 // 4 bytes each column
      _IPv6ColumnSize = 16 + ((_DBColumn - 1) << 2) // 4 bytes each column, except IPFrom column which is 16 bytes

      COUNTRY_POSITION_OFFSET = if (IP2Proxy.COUNTRY_POSITION(_DBType) != 0) (IP2Proxy.COUNTRY_POSITION(_DBType) - 2) << 2
      else 0
      REGION_POSITION_OFFSET = if (IP2Proxy.REGION_POSITION(_DBType) != 0) (IP2Proxy.REGION_POSITION(_DBType) - 2) << 2
      else 0
      CITY_POSITION_OFFSET = if (IP2Proxy.CITY_POSITION(_DBType) != 0) (IP2Proxy.CITY_POSITION(_DBType) - 2) << 2
      else 0
      ISP_POSITION_OFFSET = if (IP2Proxy.ISP_POSITION(_DBType) != 0) (IP2Proxy.ISP_POSITION(_DBType) - 2) << 2
      else 0
      PROXYTYPE_POSITION_OFFSET = if (IP2Proxy.PROXYTYPE_POSITION(_DBType) != 0) (IP2Proxy.PROXYTYPE_POSITION(_DBType) - 2) << 2
      else 0
      DOMAIN_POSITION_OFFSET = if (IP2Proxy.DOMAIN_POSITION(_DBType) != 0) (IP2Proxy.DOMAIN_POSITION(_DBType) - 2) << 2
      else 0
      USAGETYPE_POSITION_OFFSET = if (IP2Proxy.USAGETYPE_POSITION(_DBType) != 0) (IP2Proxy.USAGETYPE_POSITION(_DBType) - 2) << 2
      else 0
      ASN_POSITION_OFFSET = if (IP2Proxy.ASN_POSITION(_DBType) != 0) (IP2Proxy.ASN_POSITION(_DBType) - 2) << 2
      else 0
      AS_POSITION_OFFSET = if (IP2Proxy.AS_POSITION(_DBType) != 0) (IP2Proxy.AS_POSITION(_DBType) - 2) << 2
      else 0
      LASTSEEN_POSITION_OFFSET = if (IP2Proxy.LASTSEEN_POSITION(_DBType) != 0) (IP2Proxy.LASTSEEN_POSITION(_DBType) - 2) << 2
      else 0
      THREAT_POSITION_OFFSET = if (IP2Proxy.THREAT_POSITION(_DBType) != 0) (IP2Proxy.THREAT_POSITION(_DBType) - 2) << 2
      else 0
      PROVIDER_POSITION_OFFSET = if (IP2Proxy.PROVIDER_POSITION(_DBType) != 0) (IP2Proxy.PROVIDER_POSITION(_DBType) - 2) << 2
      else 0
      COUNTRY_ENABLED = (IP2Proxy.COUNTRY_POSITION(_DBType) != 0)
      REGION_ENABLED = (IP2Proxy.REGION_POSITION(_DBType) != 0)
      CITY_ENABLED = (IP2Proxy.CITY_POSITION(_DBType) != 0)
      ISP_ENABLED = (IP2Proxy.ISP_POSITION(_DBType) != 0)
      PROXYTYPE_ENABLED = (IP2Proxy.PROXYTYPE_POSITION(_DBType) != 0)
      DOMAIN_ENABLED = (IP2Proxy.DOMAIN_POSITION(_DBType) != 0)
      USAGETYPE_ENABLED = (IP2Proxy.USAGETYPE_POSITION(_DBType) != 0)
      ASN_ENABLED = (IP2Proxy.ASN_POSITION(_DBType) != 0)
      AS_ENABLED = (IP2Proxy.AS_POSITION(_DBType) != 0)
      LASTSEEN_ENABLED = (IP2Proxy.LASTSEEN_POSITION(_DBType) != 0)
      THREAT_ENABLED = (IP2Proxy.THREAT_POSITION(_DBType) != 0)
      PROVIDER_ENABLED = (IP2Proxy.PROVIDER_POSITION(_DBType) != 0)
      val _IndexBuffer = InChannel.map(FileChannel.MapMode.READ_ONLY, _IndexBaseAddr - 1, _BaseAddr - _IndexBaseAddr) // reading indexes
      _IndexBuffer.order(ByteOrder.LITTLE_ENDIAN)
      var Pointer = 0

      for (x <- _IndexArrayIPv4.indices) { // read IPv4 index
        _IndexArrayIPv4(x)(0) = _IndexBuffer.getInt(Pointer) // 4 bytes for from row
        _IndexArrayIPv4(x)(1) = _IndexBuffer.getInt(Pointer + 4) // 4 bytes for to row
        Pointer += 8
      }
      if (_IndexBaseAddrIPv6 > 0) { // read IPv6 index
        for (x <- _IndexArrayIPv6.indices) {
          _IndexArrayIPv6(x)(0) = _IndexBuffer.getInt(Pointer)
          _IndexArrayIPv6(x)(1) = _IndexBuffer.getInt(Pointer + 4)
          Pointer += 8
        }
      }
      if (_UseMemoryMappedFile) CreateMappedBytes(InChannel)
      else DestroyMappedBytes()
      LoadOK = true
    }
    finally if (RF != null) RF.close()
    LoadOK
  }

  /**
   * This function initialize the component with the BIN file path and IO mode.
   *
   * @param DatabasePath Path to the BIN database file
   * @throws IOException If an input or output exception occurred
   * @return -1 if encounter error else 0
   */
  @throws[IOException]
  def Open(DatabasePath: String): Int = Open(DatabasePath, IP2Proxy.IOModes.IP2PROXY_FILE_IO)

  /**
   * This function initialize the component with the BIN file path and IO mode.
   *
   * @param DatabasePath Path to the BIN database file
   * @param IOMode       Default is file IO
   * @throws IOException If an input or output exception occurred
   * @return -1 if encounter error else 0
   */
  @throws[IOException]
  def Open(DatabasePath: String, IOMode: IP2Proxy.IOModes.IOMode): Int = if (_DBType == 0) {
    _IPDatabasePath = DatabasePath
    if (IOMode eq IP2Proxy.IOModes.IP2PROXY_MEMORY_MAPPED) _UseMemoryMappedFile = true
    if (!LoadBIN) -1
    else 0
  }
  else 0

  /**
   * This function to query IP2Proxy data.
   *
   * @param IPAddress IP Address you wish to query
   * @throws IOException If an input or output exception occurred
   * @return IP2Proxy data
   */
  @throws[IOException]
  def ProxyQuery(IPAddress: String): ProxyResult = ProxyQuery(IPAddress, IP2Proxy.Modes.ALL)

  @throws[IOException]
  def ProxyQuery(IPAddress: String, Mode: IP2Proxy.Modes.Mode): ProxyResult = {
    val Result = new ProxyResult
    var RF: RandomAccessFile = null
    var Buf: ByteBuffer = null
    var DataBuf: ByteBuffer = null
    try {
      if (IPAddress == null || IPAddress.isEmpty) {
        Result.Is_Proxy = -1
        Result.Proxy_Type = IP2Proxy.MSG_INVALID_IP
        Result.Country_Short = IP2Proxy.MSG_INVALID_IP
        Result.Country_Long = IP2Proxy.MSG_INVALID_IP
        Result.Region = IP2Proxy.MSG_INVALID_IP
        Result.City = IP2Proxy.MSG_INVALID_IP
        Result.ISP = IP2Proxy.MSG_INVALID_IP
        Result.Domain = IP2Proxy.MSG_INVALID_IP
        Result.Usage_Type = IP2Proxy.MSG_INVALID_IP
        Result.ASN = IP2Proxy.MSG_INVALID_IP
        Result.AS = IP2Proxy.MSG_INVALID_IP
        Result.Last_Seen = IP2Proxy.MSG_INVALID_IP
        Result.Threat = IP2Proxy.MSG_INVALID_IP
        Result.Provider = IP2Proxy.MSG_INVALID_IP
        return Result
      }
      var IPNo: BigInteger = null
      var IndexAddr = 0
      var ActualIPType = 0
      var IPType = 0
      var BaseAddr = 0
      var ColumnSize = 0
      var BufCapacity = 0
      var MAX_IP_RANGE = BigInteger.ZERO
      var RowOffset: Long = 0
      var RowOffset2: Long = 0
      var BI: Array[BigInteger] = null
      var OverCapacity = false
      var RetArr: Array[String] = null
      try {
        BI = IP2No(IPAddress)
        IPType = BI(0).intValue
        IPNo = BI(1)
        ActualIPType = BI(2).intValue
        if (ActualIPType == 6) {
          RetArr = ExpandIPv6(IPAddress, IPType)
          IPType = RetArr(1).toInt
        }
      } catch {
        case _: UnknownHostException =>
          Result.Is_Proxy = -1
          Result.Proxy_Type = IP2Proxy.MSG_INVALID_IP
          Result.Country_Short = IP2Proxy.MSG_INVALID_IP
          Result.Country_Long = IP2Proxy.MSG_INVALID_IP
          Result.Region = IP2Proxy.MSG_INVALID_IP
          Result.City = IP2Proxy.MSG_INVALID_IP
          Result.ISP = IP2Proxy.MSG_INVALID_IP
          Result.Domain = IP2Proxy.MSG_INVALID_IP
          Result.Usage_Type = IP2Proxy.MSG_INVALID_IP
          Result.ASN = IP2Proxy.MSG_INVALID_IP
          Result.AS = IP2Proxy.MSG_INVALID_IP
          Result.Last_Seen = IP2Proxy.MSG_INVALID_IP
          Result.Threat = IP2Proxy.MSG_INVALID_IP
          Result.Provider = IP2Proxy.MSG_INVALID_IP
          return Result
      }
      var Pos: Long = 0
      var Low: Long = 0
      var High: Long = 0
      var Mid: Long = 0
      var IPFrom = BigInteger.ZERO
      var IPTo = BigInteger.ZERO
      // Read BIN if haven't done so
      if (_DBType == 0) if (!LoadBIN) { // problems reading BIN
        Result.Is_Proxy = -1
        Result.Proxy_Type = IP2Proxy.MSG_MISSING_FILE
        Result.Country_Short = IP2Proxy.MSG_MISSING_FILE
        Result.Country_Long = IP2Proxy.MSG_MISSING_FILE
        Result.Region = IP2Proxy.MSG_MISSING_FILE
        Result.City = IP2Proxy.MSG_MISSING_FILE
        Result.ISP = IP2Proxy.MSG_MISSING_FILE
        Result.Domain = IP2Proxy.MSG_MISSING_FILE
        Result.Usage_Type = IP2Proxy.MSG_MISSING_FILE
        Result.ASN = IP2Proxy.MSG_MISSING_FILE
        Result.AS = IP2Proxy.MSG_MISSING_FILE
        Result.Last_Seen = IP2Proxy.MSG_MISSING_FILE
        Result.Threat = IP2Proxy.MSG_MISSING_FILE
        Result.Provider = IP2Proxy.MSG_MISSING_FILE
        return Result
      }
      if (_UseMemoryMappedFile) {
        if ((_IPv4Buffer == null) || (_DBCountIPv6 > 0 && _IPv6Buffer == null) || (_MapDataBuffer == null)) {
          CreateMappedBytes()
        }
      }
      else {
        DestroyMappedBytes()
        RF = new RandomAccessFile(_IPDatabasePath, "r")
      }
      if (IPType == 4) {
        MAX_IP_RANGE = IP2Proxy.MAX_IPV4_RANGE
        High = _DBCount
        if (_UseMemoryMappedFile) {
          Buf = _IPv4Buffer.duplicate // this enables this thread to maintain its own position in a multi-threaded environment
          Buf.order(ByteOrder.LITTLE_ENDIAN)
          BufCapacity = Buf.capacity
        }
        else BaseAddr = _BaseAddr
        ColumnSize = _IPv4ColumnSize
        IndexAddr = IPNo.shiftRight(16).intValue
        Low = _IndexArrayIPv4(IndexAddr)(0)
        High = _IndexArrayIPv4(IndexAddr)(1)
      }
      else {
        if (_DBCountIPv6 == 0) {
          Result.Is_Proxy = -1
          Result.Proxy_Type = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Country_Short = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Country_Long = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Region = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.City = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.ISP = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Domain = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Usage_Type = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.ASN = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.AS = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Last_Seen = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Threat = IP2Proxy.MSG_IPV6_UNSUPPORTED
          Result.Provider = IP2Proxy.MSG_IPV6_UNSUPPORTED
          return Result
        }
        MAX_IP_RANGE = IP2Proxy.MAX_IPV6_RANGE
        High = _DBCountIPv6
        if (_UseMemoryMappedFile) {
          Buf = _IPv6Buffer.duplicate
          Buf.order(ByteOrder.LITTLE_ENDIAN)
          BufCapacity = Buf.capacity
        }
        else BaseAddr = _BaseAddrIPv6
        ColumnSize = _IPv6ColumnSize
        if (_IndexBaseAddrIPv6 > 0) {
          IndexAddr = IPNo.shiftRight(112).intValue
          Low = _IndexArrayIPv6(IndexAddr)(0)
          High = _IndexArrayIPv6(IndexAddr)(1)
        }
      }
      if (IPNo.compareTo(MAX_IP_RANGE) == 0) IPNo = IPNo.subtract(BigInteger.ONE)
      while ( {
        Low <= High
      }) {
        Mid = ((Low + High) / 2)
        RowOffset = BaseAddr + (Mid * ColumnSize)
        RowOffset2 = RowOffset + ColumnSize
        if (_UseMemoryMappedFile) OverCapacity = RowOffset2 >= BufCapacity
        IPFrom = Read32Or128(RowOffset, IPType, Buf, RF)
        IPTo = if (OverCapacity) BigInteger.ZERO
        else Read32Or128(RowOffset2, IPType, Buf, RF)
        if (IPNo.compareTo(IPFrom) >= 0 && IPNo.compareTo(IPTo) < 0) {
          var Is_Proxy = -1
          var Proxy_Type = IP2Proxy.MSG_NOT_SUPPORTED
          var Country_Short = IP2Proxy.MSG_NOT_SUPPORTED
          var Country_Long = IP2Proxy.MSG_NOT_SUPPORTED
          var Region = IP2Proxy.MSG_NOT_SUPPORTED
          var City = IP2Proxy.MSG_NOT_SUPPORTED
          var ISP = IP2Proxy.MSG_NOT_SUPPORTED
          var Domain = IP2Proxy.MSG_NOT_SUPPORTED
          var Usage_Type = IP2Proxy.MSG_NOT_SUPPORTED
          var ASN = IP2Proxy.MSG_NOT_SUPPORTED
          var AS = IP2Proxy.MSG_NOT_SUPPORTED
          var Last_Seen = IP2Proxy.MSG_NOT_SUPPORTED
          var Threat = IP2Proxy.MSG_NOT_SUPPORTED
          var Provider = IP2Proxy.MSG_NOT_SUPPORTED
          var FirstCol = 4 // IP From is 4 bytes
          if (IPType == 6) {
            FirstCol = 16 // IPv6 is 16 bytes
          }
          // read the row here after the IP From column (remaining columns are all 4 bytes)
          val RowLen = ColumnSize - FirstCol
          var Row: Array[Byte] = null
          Row = ReadRow(RowOffset + FirstCol, RowLen, Buf, RF)
          if (_UseMemoryMappedFile) {
            DataBuf = _MapDataBuffer.duplicate // this is to enable reading of a range of bytes in multi-threaded environment
            DataBuf.order(ByteOrder.LITTLE_ENDIAN)
          }
          if (PROXYTYPE_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.PROXY_TYPE) || (Mode eq IP2Proxy.Modes.IS_PROXY)) {
            Proxy_Type = ReadStr(Read32_Row(Row, PROXYTYPE_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (COUNTRY_ENABLED) {
            if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.COUNTRY_SHORT) || (Mode eq IP2Proxy.Modes.COUNTRY_LONG) || (Mode eq IP2Proxy.Modes.IS_PROXY)) {
              Pos = Read32_Row(Row, COUNTRY_POSITION_OFFSET).longValue
            }
            if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.COUNTRY_SHORT) || (Mode eq IP2Proxy.Modes.IS_PROXY)) {
              Country_Short = ReadStr(Pos, DataBuf, RF)
            }
            if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.COUNTRY_LONG)) {
              Country_Long = ReadStr(Pos + 3, DataBuf, RF)
            }
          }
          if (REGION_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.REGION)) {
            Region = ReadStr(Read32_Row(Row, REGION_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (CITY_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.CITY)) {
            City = ReadStr(Read32_Row(Row, CITY_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (ISP_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.ISP)) {
            ISP = ReadStr(Read32_Row(Row, ISP_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (DOMAIN_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.DOMAIN)) {
            Domain = ReadStr(Read32_Row(Row, DOMAIN_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (USAGETYPE_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.USAGE_TYPE)) {
            Usage_Type = ReadStr(Read32_Row(Row, USAGETYPE_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (ASN_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.ASN)) {
            ASN = ReadStr(Read32_Row(Row, ASN_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (AS_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.AS)) {
            AS = ReadStr(Read32_Row(Row, AS_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (LASTSEEN_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.LAST_SEEN)) {
            Last_Seen = ReadStr(Read32_Row(Row, LASTSEEN_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (THREAT_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.THREAT)) {
            Threat = ReadStr(Read32_Row(Row, THREAT_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (PROVIDER_ENABLED) if ((Mode eq IP2Proxy.Modes.ALL) || (Mode eq IP2Proxy.Modes.PROVIDER)) {
            Provider = ReadStr(Read32_Row(Row, PROVIDER_POSITION_OFFSET).longValue, DataBuf, RF)
          }
          if (Country_Short == "-" || Proxy_Type == "-") Is_Proxy = 0
          else if (Proxy_Type == "DCH" || Proxy_Type == "SES") Is_Proxy = 2
          else Is_Proxy = 1
          Result.Is_Proxy = Is_Proxy
          Result.Proxy_Type = Proxy_Type
          Result.Country_Short = Country_Short
          Result.Country_Long = Country_Long
          Result.Region = Region
          Result.City = City
          Result.ISP = ISP
          Result.Domain = Domain
          Result.Usage_Type = Usage_Type
          Result.ASN = ASN
          Result.AS = AS
          Result.Last_Seen = Last_Seen
          Result.Threat = Threat
          Result.Provider = Provider
          return Result
        }
        else if (IPNo.compareTo(IPFrom) < 0) High = Mid - 1
        else Low = Mid + 1
      }
      Result.Is_Proxy = -1
      Result.Proxy_Type = IP2Proxy.MSG_INVALID_IP
      Result.Country_Short = IP2Proxy.MSG_INVALID_IP
      Result.Country_Long = IP2Proxy.MSG_INVALID_IP
      Result.Region = IP2Proxy.MSG_INVALID_IP
      Result.City = IP2Proxy.MSG_INVALID_IP
      Result.ISP = IP2Proxy.MSG_INVALID_IP
      Result.Domain = IP2Proxy.MSG_INVALID_IP
      Result.Usage_Type = IP2Proxy.MSG_INVALID_IP
      Result.ASN = IP2Proxy.MSG_INVALID_IP
      Result.AS = IP2Proxy.MSG_INVALID_IP
      Result.Last_Seen = IP2Proxy.MSG_INVALID_IP
      Result.Threat = IP2Proxy.MSG_INVALID_IP
      Result.Provider = IP2Proxy.MSG_INVALID_IP
      Result
    } finally if (RF != null) RF.close()
  }

  private def ExpandIPv6(IP: String, IPType: Int): Array[String] = {
    val Tmp = "0000:0000:0000:0000:0000:"
    val PadMe = "0000"
    val HexOffset = 0xFF
    var IP2 = IP.toUpperCase
    var RetType = String.valueOf(IPType)
    if (IPType == 4) if (IP2Proxy.Pattern4.matcher(IP2).matches) IP2 = IP2.replaceAll("::", Tmp)
    else {
      val Mat = IP2Proxy.Pattern5.matcher(IP2)
      if (Mat.matches) {
        val Match = Mat.group(1)
        val Arr = Match.replaceAll("^:+", "").replaceAll(":+$", "").split(":")
        val Len = Arr.length
        val Bf = new StringBuilder(32)
        for (x <- 0 until Len) {
          val Unpadded = Arr(x)
          Bf.append(PadMe.substring(Unpadded.length) + Unpadded)
        }
        var Tmp2 = new BigInteger(Bf.toString, 16).longValue
        val Bytes: Array[Long] = Array(0, 0, 0, 0) // using long in place of bytes due to 2's complement signed issue
        for (x <- 0 until 4) {
          Bytes(x) = Tmp2 & HexOffset
          Tmp2 = Tmp2 >> 8
        }
        IP2 = IP2.replaceAll(Match + "$", ":" + Bytes(3) + "." + Bytes(2) + "." + Bytes(1) + "." + Bytes(0))
        IP2 = IP2.replaceAll("::", Tmp)
      }
    }
    else if (IPType == 6) if (IP2 == "::") {
      IP2 = IP2 + "0.0.0.0"
      IP2 = IP2.replaceAll("::", Tmp + "FFFF:")
      RetType = "4"
    }
    else {
      val Mat = IP2Proxy.Pattern4.matcher(IP2)
      if (Mat.matches) {
        val V6Part = Mat.group(1)
        val V4Part = Mat.group(2)
        val V4Arr = V4Part.split("\\.")
        val V4IntArr = new Array[Int](4)
        var Len = V4IntArr.length
        for (x <- 0 until Len) {
          V4IntArr(x) = V4Arr(x).toInt
        }
        val Part1 = (V4IntArr(0) << 8) + V4IntArr(1)
        val Part2 = (V4IntArr(2) << 8) + V4IntArr(3)
        val Part1Hex = Integer.toHexString(Part1)
        val Part2Hex = Integer.toHexString(Part2)
        val Bf = new StringBuilder(V6Part.length + 9)
        Bf.append(V6Part)
        Bf.append(PadMe.substring(Part1Hex.length))
        Bf.append(Part1Hex)
        Bf.append(":")
        Bf.append(PadMe.substring(Part2Hex.length))
        Bf.append(Part2Hex)
        IP2 = Bf.toString.toUpperCase
        val Arr = IP2.split("::")
        val LeftSide = Arr(0).split(":")
        val Bf2 = new StringBuilder(40)
        val Bf3 = new StringBuilder(40)
        val Bf4 = new StringBuilder(40)
        Len = LeftSide.length
        var TotalSegments = 0
        for (x <- 0 until Len) {
          if (LeftSide(x).nonEmpty) {
            TotalSegments += 1
            Bf2.append(PadMe.substring(LeftSide(x).length))
            Bf2.append(LeftSide(x))
            Bf2.append(":")
          }
        }
        if (Arr.length > 1) {
          val RightSide = Arr(1).split(":")
          Len = RightSide.length
          for (x <- 0 until Len) {
            if (RightSide(x).nonEmpty) {
              TotalSegments += 1
              Bf3.append(PadMe.substring(RightSide(x).length))
              Bf3.append(RightSide(x))
              Bf3.append(":")
            }
          }
        }
        val TotalSegmentsLeft = 8 - TotalSegments
        if (TotalSegmentsLeft == 6) {
          for (x <- 1 until TotalSegmentsLeft) {
            Bf4.append(PadMe)
            Bf4.append(":")
          }
          Bf4.append("FFFF:")
          Bf4.append(V4Part)
          RetType = "4"
          IP2 = Bf4.toString
        }
        else {
          for (x <- 0 until TotalSegmentsLeft) {
            Bf4.append(PadMe)
            Bf4.append(":")
          }
          Bf2.append(Bf4).append(Bf3)
          IP2 = Bf2.toString.replaceAll(":$", "")
        }
      }
      else {
        val Mat2 = IP2Proxy.Pattern6.matcher(IP2)
        if (Mat2.matches) {
          val Match = Mat2.group(1)
          val Arr = Match.replaceAll("^:+", "").replaceAll(":+$", "").split(":")
          val Len = Arr.length
          val Bf = new StringBuilder(32)
          for (x <- 0 until Len) {
            val Unpadded = Arr(x)
            Bf.append(PadMe.substring(Unpadded.length) + Unpadded)
          }
          var Tmp2 = new BigInteger(Bf.toString, 16).longValue
          val Bytes: Array[Long] = Array(0, 0, 0, 0)
          for (x <- 0 until 4) {
            Bytes(x) = Tmp2 & HexOffset
            Tmp2 = Tmp2 >> 8
          }
          IP2 = IP2.replaceAll(Match + "$", ":" + Bytes(3) + "." + Bytes(2) + "." + Bytes(1) + "." + Bytes(0))
          IP2 = IP2.replaceAll("::", Tmp + "FFFF:")
          RetType = "4"
        }
        else {
          val Arr = IP2.split("::")
          val LeftSide = Arr(0).split(":")
          val Bf2 = new StringBuilder(40)
          val Bf3 = new StringBuilder(40)
          val Bf4 = new StringBuilder(40)
          var Len = LeftSide.length
          var TotalSegments = 0
          for (x <- 0 until Len) {
            if (LeftSide(x).nonEmpty) {
              TotalSegments += 1
              Bf2.append(PadMe.substring(LeftSide(x).length))
              Bf2.append(LeftSide(x))
              Bf2.append(":")
            }
          }
          if (Arr.length > 1) {
            val RightSide = Arr(1).split(":")
            Len = RightSide.length
            for (x <- 0 until Len) {
              if (RightSide(x).nonEmpty) {
                TotalSegments += 1
                Bf3.append(PadMe.substring(RightSide(x).length))
                Bf3.append(RightSide(x))
                Bf3.append(":")
              }
            }
          }
          val TotalSegmentsLeft = 8 - TotalSegments
          for (x <- 0 until TotalSegmentsLeft) {
            Bf4.append(PadMe)
            Bf4.append(":")
          }
          Bf2.append(Bf4).append(Bf3)
          IP2 = Bf2.toString.replaceAll(":$", "")
        }
      }
    }
    val RetArr = Array(IP2, RetType)
    RetArr
  }

  private def Reverse(Arr: Array[Byte]): Unit = {
    if (Arr == null) return
    var i = 0
    var j = Arr.length - 1
    var tmp: Byte = 0
    while ( {
      j > i
    }) {
      tmp = Arr(j)
      Arr(j) = Arr(i)
      Arr(i) = tmp
      j -= 1
      i += 1
    }
  }

  @throws[IOException]
  private def ReadRow(Position: Long, MyLen: Long, Buf: ByteBuffer, RH: RandomAccessFile): Array[Byte] = {
    val Row = new Array[Byte](MyLen.toInt)
    if (_UseMemoryMappedFile) {
      Buf.position(Position.toInt)
      Buf.get(Row, 0, MyLen.toInt)
    }
    else {
      RH.seek(Position - 1)
      RH.read(Row, 0, MyLen.toInt)
    }
    Row
  }

  @throws[IOException]
  private def Read32Or128(Position: Long, IPType: Int, Buf: ByteBuffer, RH: RandomAccessFile): BigInteger = {
    if (IPType == 4) return Read32(Position, Buf, RH)
    else if (IPType == 6) return Read128(Position, Buf, RH)
    BigInteger.ZERO
  }

  @throws[IOException]
  private def Read128(Position: Long, Buf: ByteBuffer, RH: RandomAccessFile): BigInteger = {
    var RetVal = BigInteger.ZERO
    val BSize = 16
    val Bytes = new Array[Byte](BSize)
    if (_UseMemoryMappedFile) {
      Buf.position(Position.toInt)
      Buf.get(Bytes, 0, BSize)
    }
    else {
      RH.seek(Position - 1)
      RH.read(Bytes, 0, BSize)
    }
    Reverse(Bytes)
    RetVal = new BigInteger(1, Bytes)
    RetVal
  }

  @throws[IOException]
  private def Read32_Row(Row: Array[Byte], From: Int): BigInteger = {
    val Len = 4
    val Bytes = new Array[Byte](Len)
    System.arraycopy(Row, From, Bytes, 0.toInt, Len)
    Reverse(Bytes)
    new BigInteger(1, Bytes)
  }

  @throws[IOException]
  private def Read32(Position: Long, Buf: ByteBuffer, RH: RandomAccessFile): BigInteger = if (_UseMemoryMappedFile) {
    // simulate unsigned int by using long
    BigInteger.valueOf(Buf.getInt(Position.toInt) & 0xffffffffL) // use absolute offset to be thread-safe
  }
  else {
    val BSize = 4
    RH.seek(Position - 1)
    val Bytes = new Array[Byte](BSize)
    RH.read(Bytes, 0, BSize)
    Reverse(Bytes)
    new BigInteger(1, Bytes)
  }

  @throws[IOException]
  private def ReadStr(Position: Long, Buf: ByteBuffer, RH: RandomAccessFile): String = {
    var Size = 0
    var Bytes: Array[Byte] = null
    var Pos: Long = Position
    if (_UseMemoryMappedFile) {
      Pos = Pos - _MapDataOffset // position stored in BIN file is for full file, not just the mapped data segment, so need to minus
      Size = _MapDataBuffer.get(Pos.toInt)
      try {
        Bytes = new Array[Byte](Size)
        Buf.position(Pos.toInt + 1)
        Buf.get(Bytes, 0, Size)
      } catch {
        case e: NegativeArraySizeException =>
          return null
      }
    }
    else {
      RH.seek(Pos)
      Size = RH.read
      try {
        Bytes = new Array[Byte](Size)
        RH.read(Bytes, 0, Size)
      } catch {
        case e: NegativeArraySizeException =>
          return null
      }
    }
    val S = new String(Bytes)
    S
  }

  @throws[UnknownHostException]
  private def IP2No(IP: String): Array[BigInteger] = {
    var A1 = BigInteger.ZERO
    var A2 = BigInteger.ZERO
    var A3 = new BigInteger("4")
    if (IP2Proxy.Pattern1.matcher(IP).matches) { // should be IPv4
      A1 = new BigInteger("4")
      A2 = new BigInteger(String.valueOf(IPv4No(IP)))
    }
    else if (IP2Proxy.Pattern2.matcher(IP).matches || IP2Proxy.Pattern3.matcher(IP).matches || IP2Proxy.Pattern7.matcher(IP).matches) throw new UnknownHostException
    else {
      A3 = new BigInteger("6")
      val IA = InetAddress.getByName(IP)
      val Bytes = IA.getAddress
      var IPType = "0" // BigInteger needs String in the constructor
      IA match {
        case _: Inet6Address => IPType = "6"
        case _: Inet4Address => // this will run in cases of IPv4-mapped IPv6 addresses
          IPType = "4"
        case _ =>
      }
      A2 = new BigInteger(1, Bytes)
      if (A2.compareTo(IP2Proxy.FROM_6TO4) >= 0 && A2.compareTo(IP2Proxy.TO_6TO4) <= 0) { // 6to4 so need to remap to ipv4
        IPType = "4"
        A2 = A2.shiftRight(80)
        A2 = A2.and(IP2Proxy.LAST_32BITS)
        A3 = new BigInteger("4")
      }
      else if (A2.compareTo(IP2Proxy.FROM_TEREDO) >= 0 && A2.compareTo(IP2Proxy.TO_TEREDO) <= 0) { // Teredo so need to remap to ipv4
        IPType = "4"
        A2 = A2.not
        A2 = A2.and(IP2Proxy.LAST_32BITS)
        A3 = new BigInteger("4")
      }
      A1 = new BigInteger(IPType)
    }
    val BI = Array[BigInteger](A1, A2, A3)
    BI
  }

  private def IPv4No(IP: String): Long = {
    val IPs = IP.split("\\.")
    var RetVal: Long = 0
    var IPLong: Long = 0
    for (x <- 3 to 0 by -1) {
      IPLong = IPs(3 - x).toLong
      RetVal |= IPLong << (x << 3)
    }
    RetVal
  }
}