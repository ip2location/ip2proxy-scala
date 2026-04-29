import xerial.sbt.Sonatype._

val scala3Version = "3.3.1"

lazy val root = project
  .in(file("."))
  .settings(
    credentials += Credentials(baseDirectory.value / "sonatype.credentials"),

    organization := "com.ip2proxy",
    name := "ip2proxy-scala",
    version := "3.6.0",

    scalaVersion := scala3Version,

    libraryDependencies += "org.scalameta" %% "munit" % "1.2.4" % Test,
    libraryDependencies += "com.google.code.gson" % "gson" % "2.13.2",

    // Publishing Config
    publishMavenStyle := true,
    sonatypeCredentialHost := sonatypeCentralHost,
    publishTo := sonatypePublishToBundle.value,

    usePgpKeyHex("121B358E"),

    // Metadata
    licenses := Seq("MIT" -> url("https://opensource.org/licenses/MIT")),
    homepage := Some(url("https://github.com/ip2location/ip2proxy-scala")),
    scmInfo := Some(
      ScmInfo(
        url("https://github.com/ip2location/ip2proxy-scala"),
        "scm:git@github.com:ip2location/ip2proxy-scala.git"
      )
    ),
    developers := List(
      Developer(
        id = "ip2location",
        name = "IP2Location",
        email = "support@ip2location.com",
        url = url("https://www.ip2location.com")
      )
    )
  )