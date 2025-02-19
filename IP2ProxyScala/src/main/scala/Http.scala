package com.ip2proxy

import java.io.{BufferedReader, InputStreamReader}
import java.net.{HttpURLConnection, URL}

object Http {
  def get(url: URL): String = try {
    java.lang.System.setProperty("https.protocols", "TLSv1.2")
    val conn = url.openConnection.asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET")
    conn.setRequestProperty("Accept", "application/json")
    if (conn.getResponseCode != 200) return "Failed : HTTP error code : " + conn.getResponseCode
    val br = new BufferedReader(new InputStreamReader(conn.getInputStream))
    var output: String = null
    val resultFromHttp = new StringBuilder
    while ( {
      output = br.readLine
      output != null
    }) resultFromHttp.append(output).append("\n")
    br.close()
    conn.disconnect()
    resultFromHttp.toString
  } catch {
    case e: Exception =>
      throw new RuntimeException(e)
  }
}