package com.ip2proxy

import java.nio.file.Paths
import java.io.IOException
import org.scalatest._
import org.scalatest.funsuite.AnyFunSuite

class IP2ProxyTest extends AnyFunSuite with BeforeAndAfter with BeforeAndAfterAll {
  private var proxy: IP2Proxy = _
  private val binfile = "IP2PROXY-LITE-PX1.BIN"
  private var binfilepath: String = _
  private val ip = "8.8.8.8"


  override def beforeAll {
    val binpath = Paths.get("src", "test", "resources", binfile)
    binfilepath = binpath.toFile.getAbsolutePath
  }

  before {
    proxy = new IP2Proxy
  }

  test("TestOpenException") {
    assertThrows[IOException] {
      proxy.Open("dummy.bin")
    }
  }

  test("TestQueryIsProxy") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Is_Proxy == 0)
    }
  }

  test("TestQueryProxyType") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Proxy_Type == "NOT SUPPORTED")
    }
  }

  test("TestQueryCountryShort") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Country_Short == "-")
    }
  }

  test("TestQueryCountryLong") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Country_Long == "-")
    }
  }

  test("TestQueryRegion") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Region == "NOT SUPPORTED")
    }
  }

  test("TestQueryCity") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.City == "NOT SUPPORTED")
    }
  }

  test("TestQueryISP") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.ISP == "NOT SUPPORTED")
    }
  }

  test("TestQueryDomain") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Domain == "NOT SUPPORTED")
    }
  }

  test("TestQueryUsageType") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Usage_Type == "NOT SUPPORTED")
    }
  }

  test("TestQueryASN") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.ASN == "NOT SUPPORTED")
    }
  }

  test("TestQueryAS") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.AS == "NOT SUPPORTED")
    }
  }

  test("TestQueryLastSeen") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Last_Seen == "NOT SUPPORTED")
    }
  }

  test("TestQueryThreat") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Threat == "NOT SUPPORTED")
    }
  }

  test("TestQueryProvider") {
    if (proxy.Open(binfilepath) == 0) {
      val rec = proxy.GetAll(ip)
      assert(rec.Provider == "NOT SUPPORTED")
    }
  }

  after {
    proxy.Close
  }
}
