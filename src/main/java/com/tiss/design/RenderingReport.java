package com.tiss.design;

import java.io.ByteArrayOutputStream;
import java.util.logging.Level;

import org.apache.log4j.Logger;
import org.eclipse.birt.core.exception.BirtException;
import org.eclipse.birt.core.framework.Platform;
import org.eclipse.birt.report.engine.api.EngineConfig;
import org.eclipse.birt.report.engine.api.EngineException;
import org.eclipse.birt.report.engine.api.HTMLRenderOption;
import org.eclipse.birt.report.engine.api.IPDFRenderOption;
import org.eclipse.birt.report.engine.api.IRenderOption;
import org.eclipse.birt.report.engine.api.IReportRunnable;
import org.eclipse.birt.report.engine.api.IRunAndRenderTask;
import org.eclipse.birt.report.engine.api.PDFRenderOption;
import org.eclipse.birt.report.engine.api.RenderOption;
import org.eclipse.birt.report.engine.api.ReportEngine;

import com.tiss.spring.ReportRequestController;

public class RenderingReport {

	private ReportEngine engine;
	static Logger log = Logger.getLogger(ReportRequestController.class.getName());

	/**
	 * Constructor for the Rendering Report
	 */
	public RenderingReport() {

		log.info("Creating a Configuration Object for PlatForm startup");
		EngineConfig config = new EngineConfig();
		// config.setLogConfig("c:/temp", Level.FINE);
		try {
			log.info("Starting Up the Platform for Birt Report");
			Platform.startup(config);
		} catch (BirtException e) {
			log.error("There is an Exception while Starting PlateForm." , e);
			e.printStackTrace();
		}
		log.info("Declaring [Report Engine]");
		engine = new ReportEngine(config);
		engine.changeLogLevel(Level.WARNING);

	}

	/**
	 * This function renders the report in the for provided and return report in
	 * the form of byte[]
	 * 
	 * @param report_path
	 * @param format
	 * @return
	 */
	public byte[] render(String report_path, String format) {
		
		IReportRunnable report = null;
		IRunAndRenderTask task = null;
		IRenderOption options = new RenderOption();
		log.info("Object for the Render Option has been created");
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		log.info("Opening the Birt Report for Rendering");
		try {
			report = engine.openReportDesign(report_path);
		} catch (EngineException e) {
			
			log.error("There is an error in opening the Report for Rendering", e);
			e.printStackTrace();
		}
		// Create Render Task;
		 task = engine.createRunAndRenderTask(report);
		log.info("Rendering Task Object has been created");
		// Render the Design
		log.info("Setting the format of the Report to: "+format);
		options.setOutputFormat(format);
//		options.setOutputFileName("Report."+options.getOutputFormat());
		log.info("Writing the File into the outputstream object");
		options.setOutputStream(bout);
		log.info("Getting the type of repot and checking Whether html or pdf");
		if (options.getOutputFormat().equalsIgnoreCase("html")) {
			HTMLRenderOption htmlOptions = new HTMLRenderOption(options);
			htmlOptions.setImageDirectory("output/");
			htmlOptions.setHtmlPagination(false);
			htmlOptions.setHtmlRtLFlag(false);
			htmlOptions.setEmbeddable(false);
		} else if (options.getOutputFormat().equalsIgnoreCase("pdf")) {
			log.info("Creating [PDF Render] Object");
			PDFRenderOption pdfOptions = new PDFRenderOption(options);
			log.info("Setting up properties for the PDF reporting");
			pdfOptions.setOption(IPDFRenderOption.PAGE_OVERFLOW, IPDFRenderOption.OUTPUT_TO_MULTIPLE_PAGES);
		}
		log.info("Setting up render option for the report in [IRunAndRenderTask]");
		task.setRenderOption(options);
		try {
			log.info("Running the [IRunAndRenderTask]");
			task.run();
		} catch (EngineException e) {
			log.error("Exception while Redering the report", e);
			e.printStackTrace();
		}
		log.info("Closing the [IRunAndRenderTask] object");
		task.close();
		log.info("Returning the Outputstream of Report to the controller");
		return bout.toByteArray();
	}
}
