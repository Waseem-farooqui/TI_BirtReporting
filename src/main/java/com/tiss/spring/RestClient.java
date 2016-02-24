package com.tiss.spring;

import java.util.Map;

import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class RestClient {
	public String getJson(String url) {
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getMessageConverters().add(new MappingJackson2HttpMessageConverter());
		Object[] result = restTemplate.getForObject(url, Object[].class);
		try {
			return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(result);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public Map getMapJson(String url) {

		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getMessageConverters().add(new MappingJackson2HttpMessageConverter());
		Map<?, ?> result = restTemplate.getForObject(url, Map.class);
		return result;
	}
	
	public Map[] getMapArrayJson(String url) {

		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getMessageConverters().add(new MappingJackson2HttpMessageConverter());
		Map<?, ?>[] result = restTemplate.getForObject(url, Map[].class);
		return result;
	}
}
