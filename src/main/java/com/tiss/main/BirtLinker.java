package com.tiss.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.tiss.bean.AttackedOSs;
import com.tiss.bean.AttackedProtocols;
import com.tiss.bean.Attacks;
import com.tiss.bean.CncDomains;
import com.tiss.bean.CncIPs;
import com.tiss.bean.Countries;
import com.tiss.bean.DetectedMalwareHashes;
import com.tiss.bean.DetectedMalwares;
import com.tiss.bean.IPs;
import com.tiss.bean.ProbedCountriesUniqueIPs;
import com.tiss.bean.SipMethods;
import com.tiss.bean.SshPasswords;
import com.tiss.bean.SshUsernames;
import com.tiss.bean.Tools;
import com.tiss.bean.Vulnerabilities;
import com.tiss.bean.WebAttacks;
import com.tiss.bean.WebSeverities;
import com.tiss.populator.BeanPopulator;

public class BirtLinker {
	
	static Iterator<?> iterator = null;
	public static void main(String args[]){}
//		String json = null;
//		try {
//			json = getJson("E:/test.json");
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		List<?> beanPopulator = new BeanPopulator().getObjectList(json, Tools.class);
//		iterator = beanPopulator.iterator();
//		System.out.println(beanPopulator.size());

	public static String getJson(String filePath) throws IOException {

		File file = new File(filePath);
		InputStream fis = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];
		fis.read(data);
		fis.close();
		return new String(data, "UTF-8");
	}

	public void open(Object appContext, Map<String, Object> dataSetParmValues) {
		try {
			String type = dataSetParmValues.get("type").toString();
			List<?> beanPopulator = null;
			switch (type) {
			case "GlobalCountries":
			case "ProbedCountries":
			case "MalwareCountries":
			case "SipCountries":
			case "WebCountries":
			case "SshCountries":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), Countries.class);
				break;
			case "ProbedIPs":
			case "MalwareIPs":
			case "MalwareIPs10":
			case "SipRegistrarIPs":
			case "SipProxyIPs":
			case "SipOptionIPs":
			case "WebIPs":
			case "SshIPs":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), IPs.class);
				break;
			case "GlobalAttacks1":
			case "GlobalAttacks2":
			case "GlobalAttacks3":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), Attacks.class);
				break;
			case "SipTools":
			case "SshTools":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), Tools.class);
				break;
			case "AttackedOSs":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), AttackedOSs.class);
			case "AttackedProtocols":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"),
						AttackedProtocols.class);
				break;
			case "Vulnerabilities":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), Vulnerabilities.class);
				break;
			case "ProbedCountriesUniqueIPs":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"),
						ProbedCountriesUniqueIPs.class);
				break;
			case "DetectedMalwares":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"),
						DetectedMalwares.class);
				break;
			case "DetectedMalwareHashes":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"),
						DetectedMalwareHashes.class);
				break;
			case "CncIPs":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), CncIPs.class);
				break;
			case "CncDomains":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), CncDomains.class);
				break;
			case "SipAttacks":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), SipMethods.class);
				break;
			case "WebAttacks":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), WebAttacks.class);
				break;
			case "WebSeverities":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), WebSeverities.class);
				break;
			case "SshUsernames":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), SshUsernames.class);
				break;
			case "SshPasswords":
				beanPopulator = new BeanPopulator().getObjectList(dataSetParmValues.get("json"), SshPasswords.class);
				break;
			}

			iterator = beanPopulator.iterator();
		} catch (NullPointerException e) {
			e.printStackTrace();
			return;
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}

	public Object next() {
		if (iterator.hasNext())
			return iterator.next();
		return null;
	}

	public void close() {
		iterator = null;
	}

}
