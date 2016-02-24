package com.tiss.spring;

import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.eclipse.birt.core.exception.BirtException;
import org.eclipse.birt.report.model.api.activity.SemanticException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tiss.bean.ReportRequest;
import com.tiss.design.RenderingReport;
import com.tiss.design.UpdateDataSet;

@Controller
public class ReportRequestController {

	static Logger log = Logger.getLogger(ReportRequestController.class.getName());

	@RequestMapping(value = "/report", method = RequestMethod.POST, produces = "application/pdf", consumes = "application/json")
	public ResponseEntity<byte[]> processJson(@RequestBody String requestBody,
			@RequestParam(defaultValue = "2015-01-01T00:00:00", required = false) String from,
			@RequestParam(defaultValue = "", required = false) String to,
			@RequestParam(defaultValue = "pdf", required = false) String type) {

		// Getting the bean object for report population
		log.info("Creating an Object of the Bean");
		ReportRequest reportRequest = getBeanObject(requestBody);
		log.info("Successfully got the ReportRequest Object");
		
		// Getting the Reportname with its completePath
		String REPORT_NAME = getFileName("filepath");
		log.info(String.format("Got the File name from the configuration file [%s]", REPORT_NAME));
		// report request parsing
		try {
			if (to.isEmpty()) {
				log.info("Importing for the Report from {" + from + "} to {" + new Date() + "}");
				new UpdateDataSet().prepareDataSet(reportRequest, REPORT_NAME, from,
						new SimpleDateFormat("yyyy-MM-dd'T'HH:mm").format(new Date()));
			} else {
				log.info("Importing for the Report from {" + from + "} to {" + new Date() + "}");
				new UpdateDataSet().prepareDataSet(reportRequest, REPORT_NAME, from, to);
			}
			log.info("Dataset updated in the countries.rpt file ready for rendering");
		} catch (SemanticException e) {
			log.error(e);
			e.printStackTrace();
		} catch (BirtException e) {
			log.error("There is an Exception in Controller",e);
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// Rendering the Report on the bases of the file
		log.info("Sending the report for rendering");
		byte[] outresponse = new RenderingReport().render(REPORT_NAME, "pdf");
		log.info("Report rendering completed sending in response");
		return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/pdf")).body(outresponse);
	} // End of processJson

	/**
	 * The function will populate the pojos on the bases of the request.
	 * 
	 * @param requestBody
	 * @return ClassObject
	 */
	public ReportRequest getBeanObject(String requestBody) {

		ReportRequest reportRequest = null;

		log.info("In the Bean populator function of Spring class");

		// System.out.println(this.getClass().getProtectionDomain().getCodeSource().getLocation());
		try {
			reportRequest = new ObjectMapper().readValue(requestBody, ReportRequest.class);

			log.info("Populated the ReportRequest beans with the requestBody Object");

		} catch (IllegalArgumentException e) {
			System.err.println("Require a Single value Constructor");
			log.error("IllegalArgumentException while populating ReportRequest beans \n" + e);
		} catch (JsonParseException e) {
			e.printStackTrace();
			log.error("There is an Exception in Controller",e);
		} catch (JsonMappingException e) {
			e.printStackTrace();
			log.error("There is an Exception in Controller",e);
		} catch (IOException e) {
			e.printStackTrace();
			log.error("There is an Exception in Controller",e);
		}
		return reportRequest;
	}

	/**
	 * Function return the value on the bases of key
	 * 
	 * @param key
	 * @return value
	 */
	public static String getFileName(String key) {

		Properties prop = new Properties();
		InputStream input = null;
		input = Thread.currentThread().getContextClassLoader().getResourceAsStream("config.properties");
		if (input == null) {
			System.out.println("Sorry, unable to find " + "config.properties");
		}
		// load a properties file from class path, inside static method
		try {
			prop.load(input);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return prop.getProperty(key);
	}

	public void testCode() {
		// Thread.currentThread().getContextClassLoader().getResource(REPORT_NAME).getFile().toString();

		// ClassLoader classLoader = getClass().getClassLoader();
		// File file = new File(classLoader.getResource(REPORT_NAME).getFile());
		

		// set this if you want your image source url to be altered
		// If using the setBaseImageURL, make sure
		// to set image handler to HTMLServerImageHandler
		// htmlOptions.setBaseImageURL("http://myhost/prependme?image=");
	}

}
