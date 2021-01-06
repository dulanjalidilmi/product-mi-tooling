#!/bin/sh
# ---------------------------------------------------------------------------
#  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PRG="$0"
PRGDIR=`dirname "$PRG"`

# Only set DASHBOARD_HOME if not already set
[ -z "$DASHBOARD_HOME" ] && DASHBOARD_HOME=`cd "$PRGDIR/.." ; pwd`
export DASHBOARD_HOME=$DASHBOARD_HOME
for t in "$DASHBOARD_HOME"/lib/*.jar
do
    CARBON_CLASSPATH="$CARBON_CLASSPATH":$t
done
if [ -z "$JAVACMD" ] ; then
   if [ -n "$JAVA_HOME"  ] ; then
     if [ -x "$JAVA_HOME/jre/sh/java" ] ; then
       # IBM's JDK on AIX uses strange locations for the executables
       JAVACMD="$JAVA_HOME/jre/sh/java"
     else
       JAVACMD="$JAVA_HOME/bin/java"
     fi
   else
     JAVACMD=java
   fi
 fi
 # ----- Process the input command ----------------------------------------------
 args=""
 for c in $*
 do
     if [ "$c" = "--debug" ] || [ "$c" = "-debug" ] || [ "$c" = "debug" ]; then
           CMD="--debug"
           continue
     elif [ "$CMD" = "--debug" ]; then
           if [ -z "$PORT" ]; then
                 PORT=$c
           fi
     elif [ "$c" = "--stop" ] || [ "$c" = "-stop" ] || [ "$c" = "stop" ]; then
           CMD="stop"
     elif [ "$c" = "--start" ] || [ "$c" = "-start" ] || [ "$c" = "start" ]; then
           CMD="start"
     elif [ "$c" = "--version" ] || [ "$c" = "-version" ] || [ "$c" = "version" ]; then
           CMD="version"
     elif [ "$c" = "--restart" ] || [ "$c" = "-restart" ] || [ "$c" = "restart" ]; then
           CMD="restart"
     else
         args="$args $c"
     fi
 done

 if [ "$CMD" = "--debug" ]; then
   if [ "$PORT" = "" ]; then
     echo " Please specify the debug port after the --debug option"
     exit 1
   fi
   if [ -n "$JAVA_OPTS" ]; then
     echo "Warning !!!. User specified JAVA_OPTS will be ignored, once you give the --debug option."
   fi
   CMD="RUN"
   JAVA_OPTS="-Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=$PORT"
   echo "Please start the remote debugging client to continue..."
 fi
 if [ ! -x "$JAVACMD" ] ; then
   echo "Error: JAVA_HOME is not defined correctly."
   echo " CARBON cannot execute $JAVACMD"
   exit 1
 fi
 java \
 $JAVA_OPTS \
 -cp $CARBON_CLASSPATH \
 org.wso2.micro.integrator.dashboard.bootstrap.Bootstrap
