#include <libxml/xpath.h>

#include <cstring>
#include <sstream>

uint32_t convertInt(unsigned char* str) {
    return 0;
}


unsigned char* getPublicKey() {
    xmlInitParser();

    xmlDoc *doc = xmlReadFile("settings.xml", NULL, 0);
    if (doc == nullptr) {
	    printf("Error: unable to parse settings file");
	    return nullptr;
    }

    xmlXPathContext *xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == nullptr) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc); 
        return nullptr;
    }

    const char* xpath_expr = "//key";
    xmlXPathObject *xpathObj = xmlXPathEvalExpression(BAD_CAST xpath_expr, xpathCtx);
    if(xpathObj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression\n");
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return nullptr;
    }

    if(xmlXPathNodeSetIsEmpty(xpathObj->nodesetval)){
		xmlXPathFreeObject(xpathObj);
        printf("No result\n");
		xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return nullptr;
    }

    unsigned char* result = new unsigned char[256];
    strcpy( reinterpret_cast<char*>(result), reinterpret_cast<const char*>(xmlNodeGetContent(xpathObj->nodesetval->nodeTab[0])) );

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    xmlCleanupParser();

    return result;
}

unsigned char* getIV() {
    xmlInitParser();

    xmlDoc *doc = xmlReadFile("settings.xml", NULL, 0);
    if (doc == nullptr) {
	    printf("Error: unable to parse settings file");
	    return nullptr;
    }

    xmlXPathContext *xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == nullptr) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc); 
        return nullptr;
    }

    const char* xpath_expr = "//iv";
    xmlXPathObject *xpathObj = xmlXPathEvalExpression(BAD_CAST xpath_expr, xpathCtx);
    if(xpathObj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression\n");
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return nullptr;
    }

    if(xmlXPathNodeSetIsEmpty(xpathObj->nodesetval)){
		xmlXPathFreeObject(xpathObj);
        printf("No result\n");
		xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return nullptr;
    }

    unsigned char* result = new unsigned char[256];
    strcpy( reinterpret_cast<char*>(result), reinterpret_cast<const char*>(xmlNodeGetContent(xpathObj->nodesetval->nodeTab[0])) );

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    xmlCleanupParser();

    return result;
}