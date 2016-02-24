package com.tiss.bean;

public class ReportRequest {

	private String dateFrom;
	private String dateTo;
	private boolean globalCountries;
	private boolean globalAttacks1;
	private boolean globalAttacks2;
	private boolean globalAttacks3;
	private boolean attackedOSs;
	private boolean attackedProtocols;
	private boolean vulnerabilities;
	private boolean probedCountries;
	private boolean probedCountriesUniqueIPs;
	private boolean probedIPs;
	private boolean malwareCountries;
	private boolean malwareIPs;
	private boolean malwareIPs10;
	private boolean detectedMalware;
	private boolean detectedMalwareHashes;
	private boolean cncIPs;
	private boolean cncDomains;
	private boolean sipCountries;
	private boolean sipAttacks;
	private boolean sipRegistrarIPs;
	private boolean sipProxyIPs;
	private boolean sipOptionIPs;
	private boolean sipTools;
	private boolean webCountries;
	private boolean webIPs;
	private boolean webAttacks;
	private boolean webSeverities;
	private boolean sshCountries;
	private boolean sshIPs;
	private boolean sshUsernames;
	private boolean sshPasswords;
	private boolean sshTools;
	
	
	public ReportRequest() {
		//System.out.println("Default");
		this.dateFrom = "1971-01-01T00:00:00";
		this.dateTo = null;
		this.globalCountries = false;
		this.globalAttacks1 = false;
		this.globalAttacks2 = false;
		this.globalAttacks3 = false;
		this.attackedOSs = false;
		this.attackedProtocols = false;
		this.vulnerabilities = false;
		this.probedCountries = false;
		this.probedCountriesUniqueIPs = false;
		this.probedIPs = false;
		this.malwareCountries = false;
		this.malwareIPs = false;
		this.malwareIPs10 = false;
		this.detectedMalware = false;
		this.detectedMalwareHashes = false;
		this.cncIPs = false;
		this.cncDomains = false;
		this.sipCountries = false;
		this.sipAttacks = false;
		this.sipRegistrarIPs =false;
		this.sipProxyIPs = false;
		this.sipOptionIPs = false;
		this.sipTools = false;
		this.webCountries = false;
		this.webIPs = false;
		this.webAttacks = false;
		this.webSeverities = false;
		this.sshCountries = false;
		this.sshIPs = false;
		this.sshUsernames = false;
		this.sshPasswords = false;
		this.sshTools = false;
	}
	
	public String getDateFrom() {
		return dateFrom;
	}
	public void setDateFrom(String dateFrom) {
		this.dateFrom = dateFrom;
	}
	public String getDateTo() {
		return dateTo;
	}
	public void setDateTo(String dateTo) {
		this.dateTo = dateTo;
	}
	public boolean isGlobalCountries() {
		return globalCountries;
	}
	public void setGlobalCountries(boolean globalCountries) {
		this.globalCountries = globalCountries;
	}
	public boolean isGlobalAttacks1() {
		return globalAttacks1;
	}
	public void setGlobalAttacks1(boolean globalAttacks1) {
		this.globalAttacks1 = globalAttacks1;
	}
	public boolean isGlobalAttacks2() {
		return globalAttacks2;
	}
	public void setGlobalAttacks2(boolean globalAttacks2) {
		this.globalAttacks2 = globalAttacks2;
	}
	public boolean isGlobalAttacks3() {
		return globalAttacks3;
	}
	public void setGlobalAttacks3(boolean globalAttacks3) {
		this.globalAttacks3 = globalAttacks3;
	}
	public boolean isAttackedOSs() {
		return attackedOSs;
	}
	public void setAttackedOSs(boolean attackedOSs) {
		this.attackedOSs = attackedOSs;
	}
	public boolean isAttackedProtocols() {
		return attackedProtocols;
	}
	public void setAttackedProtocols(boolean attackedProtocols) {
		this.attackedProtocols = attackedProtocols;
	}
	public boolean isVulnerabilities() {
		return vulnerabilities;
	}
	public void setVulnerabilities(boolean vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}
	public boolean isProbedCountries() {
		return probedCountries;
	}
	public void setProbedCountries(boolean probedCountries) {
		this.probedCountries = probedCountries;
	}
	public boolean isProbedCountriesUniqueIPs() {
		return probedCountriesUniqueIPs;
	}
	public void setProbedCountriesUniqueIPs(boolean probedCountriesUniqueIPs) {
		this.probedCountriesUniqueIPs = probedCountriesUniqueIPs;
	}
	public boolean isProbedIPs() {
		return probedIPs;
	}
	public void setProbedIPs(boolean probedIPs) {
		this.probedIPs = probedIPs;
	}
	public boolean isMalwareCountries() {
		return malwareCountries;
	}
	public void setMalwareCountries(boolean malwareCountries) {
		this.malwareCountries = malwareCountries;
	}
	public boolean isMalwareIPs() {
		return malwareIPs;
	}
	public void setMalwareIPs(boolean malwareIPs) {
		this.malwareIPs = malwareIPs;
	}
	public boolean isMalwareIPs10() {
		return malwareIPs10;
	}
	public void setMalwareIPs10(boolean malwareIPs10) {
		this.malwareIPs10 = malwareIPs10;
	}
	public boolean isDetectedMalware() {
		return detectedMalware;
	}
	public void setDetectedMalware(boolean detectedMalware) {
		this.detectedMalware = detectedMalware;
	}
	public boolean isDetectedMalwareHashes() {
		return detectedMalwareHashes;
	}
	public void setDetectedMalwareHashes(boolean detectedMalwareHashes) {
		this.detectedMalwareHashes = detectedMalwareHashes;
	}
	public boolean isCncIPs() {
		return cncIPs;
	}
	public void setCncIPs(boolean cncIPs) {
		this.cncIPs = cncIPs;
	}
	public boolean isCncDomains() {
		return cncDomains;
	}
	public void setCncDomains(boolean cncDomains) {
		this.cncDomains = cncDomains;
	}
	public boolean isSipCountries() {
		return sipCountries;
	}
	public void setSipCountries(boolean sipCountries) {
		this.sipCountries = sipCountries;
	}
	public boolean isSipAttacks() {
		return sipAttacks;
	}
	public void setSipAttacks(boolean sipAttacks) {
		this.sipAttacks = sipAttacks;
	}
	public boolean isSipRegistrarIPs() {
		return sipRegistrarIPs;
	}
	public void setSipRegistrarIPs(boolean sipRegistrarIPs) {
		this.sipRegistrarIPs = sipRegistrarIPs;
	}
	public boolean isSipProxyIPs() {
		return sipProxyIPs;
	}
	public void setSipProxyIPs(boolean sipProxyIPs) {
		this.sipProxyIPs = sipProxyIPs;
	}
	public boolean isSipOptionIPs() {
		return sipOptionIPs;
	}
	public void setSipOptionIPs(boolean sipOptionIPs) {
		this.sipOptionIPs = sipOptionIPs;
	}
	public boolean isSipTools() {
		return sipTools;
	}
	public void setSipTools(boolean sipTools) {
		this.sipTools = sipTools;
	}
	public boolean isWebCountries() {
		return webCountries;
	}
	public void setWebCountries(boolean webCountries) {
		this.webCountries = webCountries;
	}
	public boolean isWebIPs() {
		return webIPs;
	}
	public void setWebIPs(boolean webIPs) {
		this.webIPs = webIPs;
	}
	public boolean isWebAttacks() {
		return webAttacks;
	}
	public void setWebAttacks(boolean webAttacks) {
		this.webAttacks = webAttacks;
	}
	public boolean isWebSeverities() {
		return webSeverities;
	}
	public void setWebSeverities(boolean webSeverities) {
		this.webSeverities = webSeverities;
	}
	public boolean isSshCountries() {
		return sshCountries;
	}
	public void setSshCountries(boolean sshCountries) {
		this.sshCountries = sshCountries;
	}
	public boolean isSshIPs() {
		return sshIPs;
	}
	public void setSshIPs(boolean sshIPs) {
		this.sshIPs = sshIPs;
	}
	public boolean isSshUsernames() {
		return sshUsernames;
	}
	public void setSshUsernames(boolean sshUsernames) {
		this.sshUsernames = sshUsernames;
	}
	public boolean isSshPasswords() {
		return sshPasswords;
	}
	public void setSshPasswords(boolean sshPasswords) {
		this.sshPasswords = sshPasswords;
	}
	public boolean isSshTools() {
		return sshTools;
	}
	public void setSshTools(boolean sshTools) {
		this.sshTools = sshTools;
	}
}
