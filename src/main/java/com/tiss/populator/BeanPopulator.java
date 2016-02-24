package com.tiss.populator;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;


public class BeanPopulator {
	
	public List<?> getObjectList(Object json, Class<?> beanClassToPopulate){
		ObjectMapper mapper = new ObjectMapper();
		List<?> beanList = null;
		try{
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			beanList = mapper.readValue(json.toString(), TypeFactory.defaultInstance().constructCollectionType(List.class,beanClassToPopulate));
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		/*for(int i=0;i<beanList.size();i++){
			Attacks a = (Attacks) beanList.get(i);
			System.out.println(a.getTotal());
		}*/
		return beanList;
	}
}
