#pragma once

#include <libxml/xpath.h>
#include <unordered_map>
#include <cstring>

class SettingsReader {
public:
    SettingsReader(const std::string path) {
        xmlInitParser();
        doc_ = xmlReadFile(path.c_str(), NULL, 0);
        if (!doc_) {
            throw std::runtime_error("unable to parse settings file");
        }


        xpath_ctx_ = xmlXPathNewContext(doc_);
        if (!xpath_ctx_) {
            throw std::runtime_error("unable to create new XPath context");
        }
    }

    std::string ReadSetting(const std::string& name, const std::string& def = "") {
        std::string xpath_expr = "//" + name;
        xpath_obj_ = xmlXPathEvalExpression(BAD_CAST xpath_expr.c_str(), xpath_ctx_);
        if(!xpath_obj_) {
            throw std::runtime_error("unable to evaluate xpath expression");
        }

        if(xmlXPathNodeSetIsEmpty(xpath_obj_->nodesetval)){
            if (!def.empty()) {
                return def;
            }
            else {
                throw std::runtime_error("setting is absent and no default value is set");
            }
        }

        unsigned char* result = new unsigned char[256];
        strcpy( reinterpret_cast<char*>(result),
            reinterpret_cast<const char*>(xmlNodeGetContent(xpath_obj_->nodesetval->nodeTab[0])) );
        return (char*)result;
    }

    ~SettingsReader() {
        xmlXPathFreeObject(xpath_obj_);
        xmlXPathFreeContext(xpath_ctx_); 
        xmlFreeDoc(doc_); 
        xmlCleanupParser();
    }

private:
    xmlDoc *doc_;
    xmlXPathContext *xpath_ctx_;
    xmlXPathObject *xpath_obj_;
    std::string path_;
};