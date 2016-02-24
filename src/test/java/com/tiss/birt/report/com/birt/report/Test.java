package com.tiss.birt.report.com.birt.report;

import java.net.URL;
import java.net.URLClassLoader;

public class Test {

	 public static void main (String args[]) {
		 	
	        /*ClassLoader cl = ClassLoader.getSystemClassLoader();

	        URL[] urls = ((URLClassLoader)cl).getURLs();

	        for(URL url: urls){
	        	System.out.println(url.getFile());
	        }*/
//	        System.out.println(System.getProperty("catalina.base"));
		 String parms[]= {"20","30","40","50"};
		 
		 System.out.println(String.format("Calling the top Attacking Countries by size=[%s] and from=[%s] and to=[%s]",parms));
	         
	   }
}
