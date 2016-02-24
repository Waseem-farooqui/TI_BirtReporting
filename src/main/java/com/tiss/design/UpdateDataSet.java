package com.tiss.design;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.apache.log4j.Logger;
import org.eclipse.birt.core.exception.BirtException;
import org.eclipse.birt.core.framework.Platform;
import org.eclipse.birt.report.model.api.DesignConfig;
import org.eclipse.birt.report.model.api.DesignElementHandle;
import org.eclipse.birt.report.model.api.Expression;
import org.eclipse.birt.report.model.api.ExpressionType;
import org.eclipse.birt.report.model.api.IDesignEngine;
import org.eclipse.birt.report.model.api.IDesignEngineFactory;
import org.eclipse.birt.report.model.api.OdaDataSetHandle;
import org.eclipse.birt.report.model.api.PropertyHandle;
import org.eclipse.birt.report.model.api.ReportDesignHandle;
import org.eclipse.birt.report.model.api.SessionHandle;
import org.eclipse.birt.report.model.api.StructureFactory;
import org.eclipse.birt.report.model.api.TextItemHandle;
import org.eclipse.birt.report.model.api.activity.SemanticException;
import org.eclipse.birt.report.model.api.elements.DesignChoiceConstants;
import org.eclipse.birt.report.model.api.elements.structures.HideRule;
import org.eclipse.birt.report.model.api.elements.structures.OdaDataSetParameter;
import org.eclipse.birt.report.model.api.metadata.PropertyValueException;
import org.eclipse.birt.report.model.elements.ReportItem;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.icu.util.ULocale;
import com.tiss.bean.ReportRequest;
import com.tiss.bean.Vulnerabilities;
import com.tiss.spring.ReportRequestController;
import com.tiss.spring.RestClient;

public class UpdateDataSet {

	ReportDesignHandle designHandle = null;
	OdaDataSetHandle dataset = null;
	String REPORT_NAME = null;
	static Logger log = Logger.getLogger(UpdateDataSet.class.getName());
	HideRule hideRule = null;

	/**
	 * Function updates the Dateset on the bases of the reportRequest beans
	 * status Add the parameter on the bases of Service call on the system
	 * 
	 * @param reportRequest
	 * @param REPORT_NAME
	 * @param fromDate
	 * @param toDate
	 * @throws BirtException
	 * @throws IOException 
	 */
	public void prepareDataSet(ReportRequest reportRequest, String REPORT_NAME, String fromDate, String toDate)
			throws BirtException, IOException {

		log.info("In the prepare dataset function of the UpdateDataSet Class");
		log.info("Setting up the name of the report :" + REPORT_NAME);
		this.REPORT_NAME = REPORT_NAME;
		Map<?, ?> result = null;
		Map<?, ?>[] globalAttacksMap = null;
		Map<?, ?>[] malwareMap = null;
		String jsonMalwares = null;
		String textProbingAttacks = "The correlated information from different sensors reveals "
				+ "that there were more than <b>%s</b> number of connection attempts to Pakistan "
				+ "cyberspace from all over the world.More than <b>%s</b> unique "
				+ "IP addresses tried to establish a connection with our deployed sensors through-out Pakistan "
				+ "for at-least one time. After thorough automated analysis and correlation, most of these "
				+ "connection attempts were classified as malicious and were doing intense scanning for "
				+ "figuring out running services (particularly the vulnerable ones) over Pakistan cyberspace. "
				+ "One of the top IP address that established most number of connections was found to "
				+ "be <b>%s</b> with more than <b>%s</b> connections. The origin of this IP address was found to be <b>%s</b>.";
		String textMalwareAttacks = "Malware attacks are the major threats being faced by Pakistani organizations. "
				+ "Using the Internet, attackers employ unique malware based techniques to infect their target "
				+ "systems for different reasons varying from creating mere nuisance to stealing credentials to "
				+ "eavesdropping on communication to capturing proprietary and highly confidential information. "
				+ "Attackers scan the Internet to look-out for vulnerable services and try to exploit them to gain "
				+ "access to the system and ultimately the network. Often root-kits (type of malware) are used to "
				+ "take over and maintain control of a compromised system. The following section of the report will "
				+ "present the latest trends of malware based attacks which were identified based on the information "
				+ "gathered from our sensors during the <b>%s </b>to <b>%s</b>. The correlated information from different "
				+ "sensors reveals that there were more than <b>%s</b> materialized malware attacks that were launched "
				+ "in this period. There were more than <b>%s</b> unique IP addresses that succeeded in exploiting "
				+ "a particular vulnerability and uploaded some malware. One of the top IP addresses that initiated "
				+ "most number of attacks was found to be <b>%s</b> with more than <b>%s</b> successful attacks. "
				+ "The origin of this IP address was found to be <b>%s</b>. "
				+ "The most number of attacks were launched by exploiting MS08-067, MS08-068, MS09-001 "
				+ "vulnerabilities, which could allow remote code execution."
				+ "Furthermore we have detected <b>%s</b> Malware Variants.";
		String textSshUsernames = "Below table lists the most user attempts seen in Pakistan for SSH. The <b>%s</b> "
				+ "username was tried the most number of times. It is strongly recommended to avoid such user names"
				+ " or use complex user names or two factor authentications.";
		String textSshPasswords = "Below table lists the most attempted passwords. The password <b>%s</b> was tried the "
				+ "most number of times. It is strongly recommended to avoid these types of passwords.";

		log.info("Calling the SetBirtEnvoirment Function");
		setupBirtEnviroment();
		addHideRule();
		log.info("Creating Object of the Rest Client Class for accessing the Responses of the TI Services");
		RestClient restClient = new RestClient();

		// testCode();

		log.info(String.format("Calling the top Attacking Countries by size=[%s] and from=[%s] and to=[%s]", "10",
				fromDate, toDate));
		String jsonGlobalCountries = restClient.getJson(
				"http://115.186.132.18:8080/TI/global/attacking-countries?size=10&from=" + fromDate + "&to=" + toDate);
		log.info("Starting Try Catch for converting Json String to Map");
		try {
			log.info("Converting [GlobalAttacksCountries] Response String to map[] object");
			globalAttacksMap = new ObjectMapper().readValue(jsonGlobalCountries, Map[].class);
		} catch (JsonParseException e) {
			log.error("Exception while Converting [GlobalAttackCountries] to Map[]", e);
			e.printStackTrace();
		} catch (JsonMappingException e) {
			log.error("Exception while Converting [GlobalAttackCountries] to Map[]", e);
			e.printStackTrace();
		} catch (IOException e) {
			log.error("Exception while Converting [GlobalAttackCountries] to Map[]", e);
			e.printStackTrace();
		}
		// ***** Global Attacked Countries******

		log.info("Checking the Condition for hiding the [GlobalDataAnalysis Label and Text]");
		if (!reportRequest.isGlobalCountries() && !reportRequest.isGlobalAttacks1() && !reportRequest.isGlobalAttacks2()
				&& !reportRequest.isGlobalAttacks3() && !reportRequest.isAttackedProtocols()
				&& !reportRequest.isVulnerabilities()) {

			log.info("Condition [Successful] for hiding [GlobalDataAnalysis Label and Text]");
			hideElement("LabelGlobalAnalysis");
			hideElement("TextGlobalAnalysis");
		} else {
			log.info("Condition [unSuccessful] for hiding [GlobalDataAnalysis Label and Text]");
			visibleElement("LabelGlobalAnalysis");
			visibleElement("TextGlobalAnalysis");
		}

		log.info("Checking the Condition for hiding the [GlobalDataCountries]");
		if (reportRequest.isGlobalCountries()) {

			log.info("[Global Countries] is [enabled] making its data visible");
			visibleElement("ChartGlobalCountries");
			visibleElement("LabelGlobalCountries");
			visibleElement("TextGlobalCountries");

			log.info("Finding Adding [GlobalCountries] DataSet the json parameter to it");
			addParameter(getDataSet("GlobalCountries"), "json", jsonGlobalCountries, 1);
			addParameter(getDataSet("GlobalCountries"), "type", "GlobalCountries", 2);

		} else {
			log.info("[GlobalCountries] is [Disabled] making its data invisible");
			hideElement("ChartGlobalCountries");
			hideElement("LabelGlobalCountries");
			hideElement("TextGlobalCountries");
		}

		log.info("Checking the Condition for hiding the [GlobalAttacks1]");
		if (reportRequest.isGlobalAttacks3()) {

			log.info("[GlobalAttacks1] is enabled making its data visible");
			visibleElement("ChartGlobalAttacks1");
			// ChartWithAxes chart = (ChartWithAxes)
			// designHandle.findElement("ChartGlobalAttacks1");
			// chart.getTitle().getLabel().getCaption().setValue("Attack from
			// global");
			visibleElement("LabelGlobalAttacks1");
			visibleElement("TextGlobalAttacks1");

			log.info("[GlobalAttacks2] is enabled making its data visible");
			visibleElement("ChartGlobalAttacks2");

			log.info("[GlobalAttacks3] is enabled making its data visible");
			visibleElement("ChartGlobalAttacks3");

			log.info("Finding Adding [GlobalAttacks1] DataSet the json parameter to it");
			addParameter(getDataSet("GlobalAttacks1"), "json",
					restClient.getJson(
							"http://115.186.132.18:8080/TI/global/country/" + globalAttacksMap[0].get("countryCode")
									+ "/attack-counts?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("GlobalAttacks1"), "type", "GlobalAttacks1", 2);

			log.info("Finding Adding [GlobalAttacks2] DataSet the json parameter to it");
			addParameter(getDataSet("GlobalAttacks2"), "json",
					restClient.getJson(
							"http://115.186.132.18:8080/TI/global/country/" + globalAttacksMap[1].get("countryCode")
									+ "/attack-counts?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("GlobalAttacks2"), "type", "GlobalAttacks2", 2);

			log.info("Finding Adding [GlobalAttacks3] DataSet the json parameter to it");
			addParameter(getDataSet("GlobalAttacks3"), "json",
					restClient.getJson(
							"http://115.186.132.18:8080/TI/global/country/" + globalAttacksMap[2].get("countryCode")
									+ "/attack-counts?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("GlobalAttacks3"), "type", "GlobalAttacks3", 2);

		} else {
			log.info("[GlobalAttacks1] is [Disabled] making its data invisible");
			hideElement("ChartGlobalAttacks1");
			hideElement("LabelGlobalAttacks1");
			hideElement("TextGlobalAttacks1");

			hideElement("ChartGlobalAttacks2");
			hideElement("ChartGlobalAttacks3");

		}

		if (reportRequest.isAttackedProtocols()) {

			log.info("[AttackedProtocols] is enabled making its data visible");
			visibleElement("ChartAttackedProtocols");
			visibleElement("LabelAttackedProtocols");
			visibleElement("TextAttackedProtocols");

			log.info("Finding Adding [AttackedProtocols] DataSet the json parameter to it");

			addParameter(getDataSet("AttackedProtocols"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/targeted-services?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("AttackedProtocols"), "type", "AttackedProtocols", 2);
		} else {
			hideElement("ChartAttackedProtocols");
			hideElement("LabelAttackedProtocols");
			hideElement("TextAttackedProtocols");

		}
		if (reportRequest.isVulnerabilities()) {

			log.info("[Vulnerabilities] is enabled making its data visible");
			visibleElement("TableVulnerabilities");
			visibleElement("LabelVulnerabilities");
			visibleElement("TextVulnerabilities");

			log.info("Finding Adding [Vulnerabilities] DataSet the json parameter to it");
			
			addParameter(getDataSet("Vulnerabilities"), "json",getJson(ReportRequestController.getFileName("vulnerabilitiesFile")),1);
			addParameter(getDataSet("Vulnerabilities"), "type", "Vulnerabilities", 2);
		} else {
			hideElement("TableVulnerabilities");
			hideElement("LabelVulnerabilities");
			hideElement("TextVulnerabilities");

		}
		// ******Probing Attacks***********

		log.info("Checking the Condition for hiding the [ProbingAttacks Label and Text]");
		if (!reportRequest.isProbedCountries() && !reportRequest.isProbedCountriesUniqueIPs()
				&& !reportRequest.isProbedIPs()) {

			log.info("Condition [Successful] for hiding [ProbingAttacks Label and Text]");
			hideElement("LabelProbingAttacks");
			hideElement("TextProbingAttacks");

		} else {
			log.info("Condition [unSuccessful] for hiding [ProbingAttacks Label and Text]");
			visibleElement("LabelProbingAttacks");
			result = restClient.getMapJson("http://115.186.132.18:8080/TI/attacks/report-info?type=probing&from="
					+ fromDate + "&to=" + toDate);

			setTextContent("TextProbingAttacks", textProbingAttacks,
					new String[] { result.get("TotalHits").toString(), result.get("DistinctIPs").toString(),
							result.get("TopIP").toString(), result.get("TopIPHits").toString(),
							result.get("Country").toString() });
			visibleElement("TextProbingAttacks");
		}
		if (reportRequest.isProbedCountries()) {

			log.info("[ProbedCountries] is enabled making its data visible");
			visibleElement("ChartProbedCountries");
			visibleElement("LabelProbedCountries");
			visibleElement("TextProbedCountries");

			log.info("Finding Adding [ProbedCountries] DataSet the json parameter to it");
			addParameter(getDataSet("ProbedCountries"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/probing/countries?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("ProbedCountries"), "type", "ProbedCountries", 2);

		} else {
			hideElement("ChartProbedCountries");
			hideElement("LabelProbedCountries");
			hideElement("TextProbedCountries");
		}

		// ****DataSet for Probed Countries Unique IPs****
		if (reportRequest.isProbedCountriesUniqueIPs()) {

			log.info("[ProbedCountriesUniqueIPs] is enabled making its data visible");
			visibleElement("ChartProbedCountriesUniqueIPs");
			visibleElement("LabelProbedCountriesUniqueIPs");
			visibleElement("TextProbedCountriesUniqueIPs");

			log.info("Finding Adding [ProbedCountriesUniqueIPs] DataSet the json parameter to it");
			addParameter(getDataSet("ProbedCountriesUniqueIPs"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/probing/unique-country-ips?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("ProbedCountriesUniqueIPs"), "type", "ProbedCountriesUniqueIPs", 2);

		} else {
			hideElement("ChartProbedCountriesUniqueIPs");
			hideElement("LabelProbedCountriesUniqueIPs");
			hideElement("TextProbedCountriesUniqueIPs");

		}
		if (reportRequest.isProbedIPs()) {

			log.info("[ProbedIPs] is enabled making its data visible");
			visibleElement("ChartProbedIPs");
			visibleElement("TableProbedIPs");
			visibleElement("LabelProbedIPs");
			visibleElement("TextProbedIPs");

			log.info("Finding Adding [ProbedIPs] DataSet the json parameter to it");
			addParameter(getDataSet("ProbedIPs"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/probing/ips?size=10&from=" + fromDate + "&to=" + toDate), 1);
			addParameter(getDataSet("ProbedIPs"), "type", "ProbedIPs", 2);

		} else {
			hideElement("ChartProbedIPs");
			hideElement("TableProbedIPs");
			hideElement("LabelProbedIPs");
			hideElement("TextProbedIPs");

		}
		// ****** Malware Attacks ***********

		if (!reportRequest.isMalwareCountries() && !reportRequest.isMalwareIPs() && !reportRequest.isMalwareIPs10()
				&& !reportRequest.isDetectedMalware() && !reportRequest.isDetectedMalwareHashes()) {
			log.info("Condition [Successful] for hiding [MalwareAttacks Label and Text]");
			hideElement("LabelMalwareAttacks");
			hideElement("TextMalwareAttacks");
		} else {

			log.info(String.format("Calling the top Malwares by size=[%s] and from=[%s] and to=[%s]", "10", fromDate,
					toDate));
			jsonMalwares = restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/malware/names?size=10&from=" + fromDate + "&to=" + toDate);
			log.info("Starting Try Catch for converting Detected Malwares String to Map");
			try {
				log.info("Converting [Detected Malwares] Response String to map[] object");
				malwareMap = new ObjectMapper().readValue(jsonMalwares, Map[].class);
			} catch (JsonParseException e) {
				log.error("Exception while Converting [Detected Malwares] to Map[]", e);
				e.printStackTrace();
			} catch (JsonMappingException e) {
				log.error("Exception while Converting [Detected Malware] to Map[]", e);
				e.printStackTrace();
			} catch (IOException e) {
				log.error("Exception while Converting [Detected Malwars] to Map[]", e);
				e.printStackTrace();
			}

			log.info("Condition [unSuccessful] for hiding [MalwareAttacks Label and Text]");
			visibleElement("LabelMalwareAttacks");
			result = restClient.getMapJson("http://115.186.132.18:8080/TI/attacks/report-info?type=malware&from="
					+ fromDate + "&to=" + toDate);
			setTextContent("TextMalwareAttacks", textMalwareAttacks,
					new String[] { fromDate.split("T")[0], toDate.split("T")[0], result.get("TotalHits").toString(),
							result.get("DistinctIPs").toString(), result.get("TopIP").toString(),
							result.get("TopIPHits").toString(), result.get("Country").toString(),
							result.get("DistinctHashes").toString() });
			visibleElement("TextMalwareAttacks");
		}

		if (reportRequest.isMalwareCountries()) {

			visibleElement("ChartMalwareCountries");
			visibleElement("LabelMalwareCountries");
			visibleElement("TextMalwareCountries");

			log.info("Finding Adding [MalwareCountries] DataSet the json parameter to it");
			addParameter(getDataSet("MalwareCountries"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/malware/countries?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("MalwareCountries"), "type", "MalwareCountries", 2);

		} else {
			hideElement("ChartMalwareCountries");
			hideElement("LabelMalwareCountries");
			hideElement("TextMalwareCountries");

		}
		if (reportRequest.isMalwareIPs()) {

			visibleElement("ChartMalwareIPs");
			visibleElement("TableMalwareIPs");
			visibleElement("LabelMalwareIPs");
			visibleElement("TextMalwareIPs");

			log.info("Finding Adding [MalwareIPs] DataSet the json parameter to it");
			addParameter(getDataSet("MalwareIPs"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/malware/ips?size=10&from=" + fromDate + "&to=" + toDate), 1);
			addParameter(getDataSet("MalwareIPs"), "type", "MalwareIPs", 2);

		} else {
			hideElement("ChartMalwareIPs");
			hideElement("TableMalwareIPs");
			hideElement("LabelMalwareIPs");
			hideElement("TextMalwareIPs");
		}
		if (reportRequest.isMalwareIPs10()) {

			visibleElement("TableMalwareIPs10");
			visibleElement("LabelMalwareIPs10");
			visibleElement("TextMalwareIPs10");

			log.info("Finding Adding [MalwareIPs10] DataSet the json parameter to it");
			addParameter(getDataSet("MalwareIPs10"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/malware/ips?minCount=10&size=0&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("MalwareIPs10"), "type", "MalwareIPs10", 2);

		} else {
			hideElement("TableMalwareIPs10");
			hideElement("LabelMalwareIPs10");
			hideElement("TextMalwareIPs10");

		}
		if (reportRequest.isDetectedMalware()) {

			visibleElement("ChartDetectedMalwares");
			visibleElement("LabelDetectedMalwares");
			visibleElement("TextDetectedMalwares");

			log.info("Finding Adding [DetectedMalwares] DataSet the json parameter to it");
			addParameter(getDataSet("DetectedMalwares"), "json", jsonMalwares, 1);
			addParameter(getDataSet("DetectedMalwares"), "type", "DetectedMalwares", 2);

		} else {
			hideElement("ChartDetectedMalwares");
			hideElement("LabelDetectedMalwares");
			hideElement("TextDetectedMalwares");

		}
		if (reportRequest.isDetectedMalwareHashes()) {

			/*
			 * Map[] hashesMap = restClient.getMapArrayJson(
			 * "http://115.186.132.18:8080/TI/attacks/malware/hashes?mal="+
			 * malwareMap[0].get("malware")+"&size=5&from=" + fromDate + "&to="
			 * + toDate); visibleElement("TableDetectedMalwareHashes");
			 * ElementFactory designFactory = designHandle.getElementFactory();
			 * 
			 * TableHandle table = (TableHandle)
			 * designHandle.findElement("TableDetectedMalwareHashes"); RowHandle
			 * row = (RowHandle) table.getDetail().get( 0 ); TextItemHandle text
			 * = designFactory.newTextItem("CellDetectedMalwareHashes");
			 * text.setContentType("html"); String hashContent = ""; for(int i=0
			 * ; i<hashesMap.length; i++ ){ hashContent =
			 * hashContent+hashesMap[i].get("hash")+"<BR>"; if(i==4) break; }
			 * text.setContent(hashContent); CellHandle cell = (CellHandle)
			 * row.getCells().get(2); cell.getContent().drop(0);
			 * //cell.getContent().add(text);
			 * 
			 * visibleElement("LabelDetectedMalwareHashes");
			 * visibleElement("TextDetectedMalwareHashes");
			 * 
			 * log.info(
			 * "Finding Adding [DetectedMalwares] DataSet the json parameter to it"
			 * ); addParameter(getDataSet("DetectedMalwares"), "json",
			 * restClient.getJson(
			 * "http://115.186.132.18:8080/TI/attacks/malware/names?size=10&from="
			 * + fromDate + "&to=" + toDate), 1);
			 * addParameter(getDataSet("DetectedMalwares"), "type",
			 * "DetectedMalwares", 2);
			 */
			hideElement("TableDetectedMalwareHashes");
			hideElement("LabelDetectedMalwareHashes");
			hideElement("TextDetectedMalwareHashes");

		} else {
			hideElement("TableDetectedMalwareHashes");
			hideElement("LabelDetectedMalwareHashes");
			hideElement("TextDetectedMalwareHashes");

		}
		// ********* SIP Attacks **********************
		if (!reportRequest.isSipCountries() && !reportRequest.isSipAttacks() && !reportRequest.isSipRegistrarIPs()
				&& !reportRequest.isSipOptionIPs() && !reportRequest.isSipProxyIPs() && !reportRequest.isSipTools()) {

			log.info("Condition [Successful] for hiding [SipHeading Label and Text]");
			hideElement("LabelSipHeading");
			hideElement("TextSipHeading");

		} else {
			log.info("Condition [unSuccessful] for hiding [SipHeading Label and Text]");
			visibleElement("LabelSipHeading");
			visibleElement("TextSipHeading");
		}
		if (reportRequest.isSipCountries()) {

			visibleElement("ChartSipCountries");
			visibleElement("LabelSipCountries");
			visibleElement("TextSipCountries");

			log.info("Finding Adding [SipCountries] DataSet the json parameter to it");
			addParameter(getDataSet("SipCountries"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/sip/countries?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SipCountries"), "type", "SipCountries", 2);

		} else {
			hideElement("ChartSipCountries");
			hideElement("LabelSipCountries");
			hideElement("TextSipCountries");

		}
		if (reportRequest.isSipAttacks()) {

			visibleElement("ChartSipAttacks");
			visibleElement("LabelSipAttacks");
			visibleElement("TextSipAttacks");

			log.info("Finding Adding [SipAttacks] DataSet the json parameter to it");
			addParameter(getDataSet("SipAttacks"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/sip/methods?size=10&from=" + fromDate + "&to=" + toDate), 1);
			addParameter(getDataSet("SipAttacks"), "type", "SipAttacks", 2);

		} else {
			hideElement("ChartSipAttacks");
			hideElement("LabelSipAttacks");
			hideElement("TextSipAttacks");
		}
		if (reportRequest.isSipRegistrarIPs()) {

			visibleElement("TableSipRegistrarIPs");
			visibleElement("LabelSipRegistrarIPs");
			visibleElement("TextSipRegistrarIPs");

			log.info("Finding Adding [SipRegistrarIPs] DataSet the json parameter to it");
			addParameter(getDataSet("SipRegistrarIPs"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/sip/registrar-flooding-ips?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SipRegistrarIPs"), "type", "SipRegistrarIPs", 2);

		} else {
			hideElement("TableSipRegistrarIPs");
			hideElement("LabelSipRegistrarIPs");
			hideElement("TextSipRegistrarIPs");
		}
		if (reportRequest.isSipOptionIPs()) {

			visibleElement("TableSipOptionIPs");
			visibleElement("LabelSipOptionIPs");
			visibleElement("TextSipOptionIPs");

			log.info("Finding Adding [SipOptionIPs] DataSet the json parameter to it");
			addParameter(getDataSet("SipOptionIPs"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/sip/options-flooding-ips?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SipOptionIPs"), "type", "SipOptionIPs", 2);

		} else {
			hideElement("TableSipOptionIPs");
			hideElement("LabelSipOptionIPs");
			hideElement("TextSipOptionIPs");

		}
		if (reportRequest.isSipProxyIPs()) {

			visibleElement("TableSipProxyIPs");
			visibleElement("LabelSipProxyIPs");
			visibleElement("TextSipProxyIPs");

			addParameter(getDataSet("SipProxyIPs"), "json",
					restClient.getJson("http://115.186.132.18:8080/TI/attacks/sip/proxy-flooding-ips?size=10&from="
							+ fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SipProxyIPs"), "type", "SipProxyIPs", 2);

		} else {
			hideElement("TableSipProxyIPs");
			hideElement("LabelSipProxyIPs");
			hideElement("TextSipProxyIPs");
		}
		if (reportRequest.isSipTools()) {

			visibleElement("ChartSipTools");
			visibleElement("LabelSipTools");
			visibleElement("TextSipTools");

			addParameter(getDataSet("SipTools"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/sip/tools?size=10&from=" + fromDate + "&to=" + toDate), 1);
			addParameter(getDataSet("SipTools"), "type", "SipTools", 2);

		} else {
			hideElement("ChartSipTools");
			hideElement("LabelSipTools");
			hideElement("TextSipTools");
		}
		// ********* WEB Attacks *************************
		if (!reportRequest.isWebCountries() && !reportRequest.isWebIPs() && !reportRequest.isWebAttacks()
				&& !reportRequest.isWebSeverities()) {

			log.info("Condition [Successful] for hiding [WebHeading Label and Text]");
			hideElement("LabelWebHeading");
			hideElement("TextWebHeading");

		} else {
			log.info("Condition [unSuccessful] for hiding [WebHeading Label and Text]");
			visibleElement("LabelWebHeading");
			visibleElement("TextWebHeading");
		}

		if (reportRequest.isWebCountries()) {

			visibleElement("ChartWebCountries");
			visibleElement("LabelWebCountries");
			visibleElement("TextWebCountries");
			log.info("Finding Adding [WebCountries] DataSet the json parameter to it");
			addParameter(getDataSet("WebCountries"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/web/countries?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("WebCountries"), "type", "WebCountries", 2);

		} else {
			hideElement("ChartWebCountries");
			hideElement("LabelWebCountries");
			hideElement("TextWebCountries");

		}
		if (reportRequest.isWebIPs()) {

			visibleElement("ChartWebIPs");
			visibleElement("TableWebIPs");
			visibleElement("LabelWebIPs");
			visibleElement("TextWebIPs");

			log.info("Finding Adding [WebIPs] DataSet the json parameter to it");
			addParameter(getDataSet("WebIPs"), "json",
					restClient.getJson(
							"http://115.186.132.18:8080/TI/attacks/web/ips?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("WebIPs"), "type", "WebIPs", 2);

		} else {
			hideElement("ChartWebIPs");
			hideElement("TableWebIPs");
			hideElement("LabelWebIPs");
			hideElement("TextWebIPs");
		}
		if (reportRequest.isWebAttacks()) {

			visibleElement("ChartWebAttacks");
			visibleElement("LabelWebAttacks");
			visibleElement("TextWebAttacks");

			log.info("Finding Adding [WebAttacks] DataSet the json parameter to it");
			addParameter(getDataSet("WebAttacks"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/web/categories?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("WebAttacks"), "type", "WebAttacks", 2);

		} else {
			hideElement("ChartWebAttacks");
			hideElement("LabelWebAttacks");
			hideElement("TextWebAttacks");

		}
		if (reportRequest.isWebAttacks()) {

			visibleElement("ChartWebSeverities");
			visibleElement("LabelWebSeverities");
			visibleElement("TextWebSeverities");

			log.info("Finding Adding [WebSeverities] DataSet the json parameter to it");
			addParameter(getDataSet("WebSeverities"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/web/severities?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("WebSeverities"), "type", "WebSeverities", 2);

		} else {
			hideElement("ChartWebSeverities");
			hideElement("LabelWebSeverities");
			hideElement("TextWebSeverities");

		}
		// ************ SSH Attacks **********************
		if (!reportRequest.isSshCountries() && !reportRequest.isSshIPs() && !reportRequest.isSshUsernames()
				&& !reportRequest.isSshPasswords() && !reportRequest.isSshTools()) {

			log.info("Condition [Successful] for hiding [SshAttacks Label and Text]");
			hideElement("LabelSshAttacks");
			hideElement("TextSshAttacks");

		} else {
			log.info("Condition [unSuccessful] for hiding [SshAttacks Label and Text]");
			visibleElement("LabelSshAttacks");
			visibleElement("TextSshAttacks");
		}
		if (reportRequest.isSshCountries()) {

			visibleElement("ChartSshCountries");
			visibleElement("LabelSshCountries");
			visibleElement("TextSshCountries");

			log.info("Finding Adding [SshCountries] DataSet the json parameter to it");
			addParameter(getDataSet("SshCountries"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/ssh/countries?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SshCountries"), "type", "SshCountries", 2);

		} else {
			hideElement("ChartSshCountries");
			hideElement("LabelSshCountries");
			hideElement("TextSshCountries");

		}
		if (reportRequest.isSshIPs()) {

			visibleElement("ChartSshIPs");
			visibleElement("TableSshIPs");
			visibleElement("LabelSshIPs");
			visibleElement("TextSshIPs");

			log.info("Finding Adding [SshIPs] DataSet the json parameter to it");
			addParameter(getDataSet("SshIPs"), "json",
					restClient.getJson(
							"http://115.186.132.18:8080/TI/attacks/ssh/ips?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SshIPs"), "type", "SshIPs", 2);

		} else {
			hideElement("ChartSshIPs");
			hideElement("TableSshIPs");
			hideElement("LabelSshIPs");
			hideElement("TextSshIPs");

		}
		if (reportRequest.isSshPasswords()) {

			result = restClient.getMapJson(
					"http://115.186.132.18:8080/TI/attacks/report-info?type=ssh&from=" + fromDate + "&to=" + toDate);
			visibleElement("TableSshPasswords");
			visibleElement("LabelSshPasswords");
			setTextContent("TextSshPasswords", textSshPasswords, new String[] { result.get("SSHPassword").toString() });
			visibleElement("TextSshPasswords");

			log.info("Finding Adding [SshPasswords] DataSet the json parameter to it");
			addParameter(getDataSet("SshPasswords"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/ssh/passwords?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SshPasswords"), "type", "SshPasswords", 2);

		} else {
			hideElement("TableSshPasswords");
			hideElement("LabelSshPasswords");
			hideElement("TextSshPasswords");

		}
		if (reportRequest.isSshUsernames()) {

			result = restClient.getMapJson(
					"http://115.186.132.18:8080/TI/attacks/report-info?type=ssh&from=" + fromDate + "&to=" + toDate);
			visibleElement("TableSshUsernames");
			visibleElement("LabelSshUsernames");
			setTextContent("TextSshUsernames", textSshUsernames, new String[] { result.get("SSHUsername").toString() });
			visibleElement("TextSshUsernames");

			log.info("Finding Adding [SshUsernames] DataSet the json parameter to it");
			addParameter(getDataSet("SshUsernames"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/ssh/usernames?size=10&from=" + fromDate + "&to=" + toDate),
					1);
			addParameter(getDataSet("SshUsernames"), "type", "SshUsernames", 2);

		} else {
			hideElement("TableSshUsernames");
			hideElement("LabelSshUsernames");
			hideElement("TextSshUsernames");

		}
		if (reportRequest.isSshTools()) {

			visibleElement("ChartSshTools");
			visibleElement("LabelSshTools");
			visibleElement("TextSshTools");

			log.info("Finding Adding [SshTools] DataSet the json parameter to it");
			addParameter(getDataSet("SshTools"), "json", restClient.getJson(
					"http://115.186.132.18:8080/TI/attacks/ssh/tools?size=10&from=" + fromDate + "&to=" + toDate), 1);
			addParameter(getDataSet("SshTools"), "type", "SshTools", 2);

		} else {
			hideElement("ChartSshTools");
			hideElement("LabelSshTools");
			hideElement("TextSshTools");

		}
		try {
			log.info("Saving the Report after adding Parameters");
			designHandle.saveAs(REPORT_NAME);
		} catch (IOException e) {
			log.error("There is an error in saving the report after adding parameters", e);
			e.printStackTrace();
		}
		log.info("Closing Design Handle of Birt Report");
		designHandle.close();
		log.info("Shuting Down the Plateform of the Birt");
		Platform.shutdown();
	}

	/**
	 * The Function will set the necessary settings for the Birt
	 * 
	 * @throws BirtException
	 */
	public void setupBirtEnviroment() throws BirtException {

		DesignConfig config = new DesignConfig();
		IDesignEngine designEngine = null;
		log.info("String Birt Platform");
		Platform.startup(config);
		IDesignEngineFactory factory = (IDesignEngineFactory) Platform
				.createFactoryObject(IDesignEngineFactory.EXTENSION_DESIGN_ENGINE_FACTORY);
		log.info("Creating Design Engine by Designe Engine Factory");
		designEngine = factory.createDesignEngine(config);
		log.info("Setting up the session by the Locale English");
		SessionHandle session = designEngine.newSessionHandle(ULocale.ENGLISH);
		// Opening the design or template
		log.info("Opening the Design Report for Updating the dataset parameters");
		designHandle = session.openDesign(REPORT_NAME);

	}

	/**
	 * Function will add the hide rule on the elements of the report
	 */
	public void addHideRule() {

		hideRule = StructureFactory.createHideRule();
		hideRule.setFormat(DesignChoiceConstants.FORMAT_TYPE_PDF);
		hideRule.setExpression("true");
	}

	public void removeParameters(String datasetName) {
		PropertyHandle ph = getDataSet("ProbedCountries").getPropertyHandle(ReportItem.PARAM_BINDINGS_PROP);
		try {
			System.out.println(ph.getItems().size());
			ph.removeItem(0);
		} catch (NullPointerException e) {
			System.out.println("No parameters Found");
		} catch (PropertyValueException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * This Functions Finds the Element with Regarding Name Add the Hide Rule
	 * and return the property
	 * 
	 * @param elementName
	 * @return elementProperty
	 */
	public void visibleElement(String elementName) {

		DesignElementHandle elementToHide = null;
		PropertyHandle elementProperty = null;
		try {
			elementToHide = designHandle.findElement(elementName);
			log.info("[" + elementName + "] is found in the report");
			elementProperty = elementToHide.getPropertyHandle(ReportItem.VISIBILITY_PROP);
			log.info(
					"[" + elementName + "] Visibility Property has configured, [" + elementName + "] is [Visible] now");
			if (elementProperty.getIntValue() > 0) {
				log.info(" [" + elementName + "] is hide unhiding it");
				try {
					for (int i = elementProperty.getIntValue() - 1; i >= 0; i--) {
						elementProperty.removeItem(i);
					}
				} catch (PropertyValueException e) {
					log.error("Exception while Unhiding  [" + elementName + "]", e);
					e.printStackTrace();
				}
			}

		} catch (NullPointerException e) {
			log.error("Exception while Finding [" + elementName + "] ", e);
		}

	}

	/**
	 * This Functions Finds the Element with Regarding Name Add the Hide Rule
	 * and hide the Element
	 * 
	 * @param elementName
	 * @return
	 */
	public void hideElement(String elementName) {
		DesignElementHandle elementToHide = null;
		try {
			elementToHide = designHandle.findElement(elementName);
			log.info("[" + elementName + "] is found in the report");
			elementToHide.getPropertyHandle(ReportItem.VISIBILITY_PROP).addItem(hideRule);
			log.info("[" + elementName + "] Visibility Property has configured, [" + elementName + "] is [Hided] now");

		} catch (NullPointerException e) {
			log.error("Exception while Finding [" + elementName + "] ", e);
		} catch (SemanticException e) {
			log.error("Unable to Hide the  [" + elementName + "] because of ", e);
			e.printStackTrace();
		}

	}

	public void addParameter(OdaDataSetHandle dataset, String name, String value, int position)
			throws SemanticException {

		PropertyHandle paramerterHandle = dataset.getPropertyHandle(OdaDataSetHandle.PARAMETERS_PROP);
		if (paramerterHandle.getIntValue() > 1) {
			for (int i = paramerterHandle.getIntValue() - 1; i >= 0; i--) {
				paramerterHandle.removeItem(i);
			}
		}
		paramerterHandle.addItem(getDataSetParameter(name, value, position));
	}

	public OdaDataSetHandle getDataSet(String datasetName) {

		dataset = (OdaDataSetHandle) designHandle.findDataSet(datasetName);
		return dataset;
	}

	public OdaDataSetParameter getDataSetParameter(String parmName, String parmValue, int position) {

		OdaDataSetParameter parm = StructureFactory.createOdaDataSetParameter();
		parm.setName(parmName);
		parm.setDataType(DesignChoiceConstants.PARAM_TYPE_STRING);
		parm.setPosition(position);
		parm.setIsInput(true);
		parm.setIsOutput(false);
		parm.setExpressionProperty("defaultValue", new Expression(parmValue, ExpressionType.CONSTANT));

		return parm;
	}

	public void setTextContent(String elementName, String content, Object args[]) {

		TextItemHandle text = (TextItemHandle) designHandle.findElement(elementName);
		try {
			text.setContent(String.format(content, args));
		} catch (SemanticException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void testCode() {
		TextItemHandle text = (TextItemHandle) designHandle.findElement("TextProbingAttacks");
		System.out.println(text.getContent());
	}

	public String getJson(String filePath) throws IOException {

		File file = new File(filePath);
		InputStream fis = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];;
		fis.read(data);
		fis.close();
		return new String(data, "UTF-8");
	}
	

}

/*
 * JUNK data // OdaDataSetDesign probedCountries = new
 * OdaDataSetDesign("ProbedCountries"); //
 * probedCountries.setDataSource(designHandle.findDataSource("Reporting Pojo"
 * ).getName());
 * 
 * // ParameterDefinition parmJson = new ParameterDefinition("json",
 * DataType.STRING_TYPE); // parmJson.setInputMode(true); //
 * parmJson.setPosition(0); //
 * parmJson.setDefaultInputValue(getJson(System.getProperty("user.dir") +
 * "/test.json"); // // ParameterDefinition parmType = new
 * ParameterDefinition("type", DataType.STRING_TYPE); //
 * parmType.setInputMode(true); // parmType.setPosition(1); //
 * parmType.setDefaultInputValue("ProbedCountries"); //
 * probedCountries.addParameter(parmJson); //
 * probedCountries.addParameter(parmType);
 * 
 * // // Module module = designHandle.getModule(); // List<DesignElement>
 * elementList = module.getAllElements(); // for(DesignElement element :
 * elementList){ // DesignElementHandle elementHandle =
 * element.getHandle(module); //
 * System.out.println(element.getName()+"\n"+element.getID()+"\n"+element.
 * getIdentifier()+"\n"+elementHandle.getDisplayLabel()+"\n\n"); // }
 * 
 * 
 * // ExtendedItemHandle probingCountriesChart = (ExtendedItemHandle) //
 * designHandle.findElement("ChartProbedCountries"); //
 * probingCountriesChart.setDataSet(dataset); //
 * System.out.println(probingCountriesChart.getDisplayLabel());
 * 
 */
// SlotHandle sh = designHandle.getBody();
// System.out.println("Contents Count: " + sh.getCount());
// Iterator it = sh.iterator();
// while (it.hasNext()) {
// DesignElementHandle de = (DesignElementHandle) it.next();
// System.out.println(de.getName());
//
// }