package org.vash.vate.compatibility;

import java.util.ArrayList;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class VTSecureSockets
{
  public static void disableSSL(SSLSocket tlsSocket, boolean client)
  {
    tlsSocket.setUseClientMode(client);
    String[] currentProtocols = tlsSocket.getEnabledProtocols();
    ArrayList<String> allowedProtocols = new ArrayList<String>();
    if (client)
    {
      for (String protocol : currentProtocols)
      {
        if (!"SSLv2Hello".equalsIgnoreCase(protocol) && !"SSLv3".equalsIgnoreCase(protocol))
        {
          allowedProtocols.add(protocol);
        }
      }
    }
    else
    {
      for (String protocol : currentProtocols)
      {
        if (!"SSLv3".equalsIgnoreCase(protocol))
        {
          allowedProtocols.add(protocol);
        }
      }
    }
    try
    {
      tlsSocket.setEnabledProtocols(allowedProtocols.toArray(new String[] {}));
    }
    catch (Throwable t)
    {
      
    }
  }
  
  public static void disableSSL(SSLServerSocket tlsSocket, boolean client)
  {
    tlsSocket.setUseClientMode(client);
    String[] currentProtocols = tlsSocket.getEnabledProtocols();
    ArrayList<String> allowedProtocols = new ArrayList<String>();
    if (client)
    {
      for (String protocol : currentProtocols)
      {
        if (!"SSLv2Hello".equalsIgnoreCase(protocol) && !"SSLv3".equalsIgnoreCase(protocol))
        {
          allowedProtocols.add(protocol);
        }
      }
    }
    else
    {
      for (String protocol : currentProtocols)
      {
        if (!"SSLv3".equalsIgnoreCase(protocol))
        {
          allowedProtocols.add(protocol);
        }
      }
    }
    try
    {
      tlsSocket.setEnabledProtocols(allowedProtocols.toArray(new String[] {}));
    }
    catch (Throwable t)
    {
      
    }
  }
}