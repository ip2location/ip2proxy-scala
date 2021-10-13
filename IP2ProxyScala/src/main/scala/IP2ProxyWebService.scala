package com.ip2proxy

import com.google.gson._
import java.net.{URL, URLEncoder}
import java.util.regex._

object IP2ProxyWebService {
  private val pattern = Pattern.compile("^[\\dA-Z]{10}$")
  private val pattern2 = Pattern.compile("^PX\\d+$")
}

class IP2ProxyWebService() {
  private var _APIKey: String = _
  private var _Package: String = _
  private var _UseSSL: Boolean = _

  /**
   * This function initializes the params for the web service.
   *
   * @param APIKey  IP2Proxy Web Service API key
   * @param Package IP2Proxy Web Service package (PX1 to PX11)
   * @throws IllegalArgumentException If an invalid parameter is specified
   */
  @throws[IllegalArgumentException]
  def Open(APIKey: String, Package: String): Unit = Open(APIKey, Package, true)

  /**
   * This function initializes the params for the web service.
   *
   * @param APIKey  IP2Proxy Web Service API key
   * @param Package IP2Proxy Web Service package (PX1 to PX11)
   * @param UseSSL  Set to true to call the web service using SSL
   * @throws IllegalArgumentException If an invalid parameter is specified
   */
  @throws[IllegalArgumentException]
  def Open(APIKey: String, Package: String, UseSSL: Boolean): Unit = {
    _APIKey = APIKey
    _Package = Package
    _UseSSL = UseSSL
    CheckParams()
  }

  /**
   * This function validates the API key and package params.
   */
  @throws[IllegalArgumentException]
  private def CheckParams(): Unit = if (!IP2ProxyWebService.pattern.matcher(_APIKey).matches) throw new IllegalArgumentException("Invalid API key.")
  else if (!IP2ProxyWebService.pattern2.matcher(_Package).matches) throw new IllegalArgumentException("Invalid package name.")

  /**
   * This function to query IP2Proxy data.
   *
   * @param IPAddress IP Address you wish to query
   * @return IP2Proxy data
   * @throws IllegalArgumentException If an invalid parameter is specified
   * @throws RuntimeException         If an exception occurred at runtime
   */
  @throws[IllegalArgumentException]
  @throws[RuntimeException]
  def IPQuery(IPAddress: String): JsonObject = try {
    CheckParams() // check here in case user haven't called Open yet
    val bf = new StringBuffer
    bf.append("http")
    if (_UseSSL) bf.append("s")
    bf.append("://api.ip2proxy.com/?key=").append(_APIKey).append("&package=").append(_Package).append("&ip=").append(URLEncoder.encode(IPAddress, "UTF-8"))
    val myUrl = bf.toString
    val myJson = Http.get(new URL(myUrl))
    JsonParser.parseString(myJson).getAsJsonObject
  } catch {
    case ex: IllegalArgumentException =>
      throw ex
    case ex2: Exception =>
      throw new RuntimeException(ex2)
  }

  /**
   * This function to check web service credit balance.
   *
   * @return Credit balance
   * @throws IllegalArgumentException If an invalid parameter is specified
   * @throws RuntimeException         If an exception occurred at runtime
   */
  @throws[IllegalArgumentException]
  @throws[RuntimeException]
  def GetCredit: JsonObject = try {
    CheckParams()
    val bf = new StringBuffer
    bf.append("http")
    if (_UseSSL) bf.append("s")
    bf.append("://api.ip2proxy.com/?key=").append(_APIKey).append("&check=true")
    val myUrl = bf.toString
    val myJson = Http.get(new URL(myUrl))
    JsonParser.parseString(myJson).getAsJsonObject
  } catch {
    case ex: IllegalArgumentException =>
      throw ex
    case ex2: Exception =>
      throw new RuntimeException(ex2)
  }
}