package com.tiss.bean;

public class ProbedCountriesUniqueIPs {
	
	private String country;
	private String countryCode;
	private int hits;
	private int uniqueIPCount;
	
	public String getCountry() {
		return country;
	}
	public void setCountry(String country) {
		this.country = country;
	}
	public String getCountryCode() {
		return countryCode;
	}
	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}
	public int getHits() {
		return hits;
	}
	public void setHits(int hits) {
		this.hits = hits;
	}
	public int getUniqueIPCount() {
		return uniqueIPCount;
	}
	public void setUniqueIPCount(int uniqueIPCount) {
		this.uniqueIPCount = uniqueIPCount;
	}

}
