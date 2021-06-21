#pragma once

#include <string>
#include <vector>
#include <regex>
#include <libxml/xpath.h>

std::vector<std::string> split(const std::string& s, char delimiter)                                                                                                                          
{                                                                                                                                                                                             
   std::vector<std::string> splits;                                                                                                                                                           
   std::string split;                                                                                                                                                                         
   std::istringstream ss(s);                                                                                                                                                                  
   while (std::getline(ss, split, delimiter))                                                                                                                                                 
   {                                                                                                                                                                                          
      splits.push_back(split);                                                                                                                                                                
   }                                                                                                                                                                                          
   return splits;                                                                                                                                                                             
}

void ReadDataSet(const std::string& path, std::vector<std::string>& out) {
    xmlInitParser();
    xmlDoc *doc = xmlReadFile(path.c_str(), NULL, 0);
    if (!doc) {
        throw std::runtime_error("unable to open dataset file");
    }

    xmlXPathContext *xpath_ctx_ = xmlXPathNewContext(doc);
    if (!xpath_ctx_) {
        throw std::runtime_error("unable to create new XPath context");
    }

    std::string xpath_expr = "//data";
    xmlXPathObject *xpath_obj = xmlXPathEvalExpression(BAD_CAST xpath_expr.c_str(), xpath_ctx_);
    if(!xpath_obj) {
        throw std::runtime_error("unable to find <data> in data file");
    }

    if(xmlXPathNodeSetIsEmpty(xpath_obj->nodesetval)) {
        throw std::runtime_error("unable to find <data> in data file");
    }   

    unsigned char* result = new unsigned char[256];
    strcpy( reinterpret_cast<char*>(result),
        reinterpret_cast<const char*>(xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[0])) );

    std::string data((char*)result);
    data = std::regex_replace(data, std::regex("^ +| +$|( ) +"), "$1");
    std::cout << "Data read: " << data << std::endl;
    out = split(data, ',');
}