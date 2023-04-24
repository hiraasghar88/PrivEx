PrivEx is an interactive user interface that helps data producers to reduce privacy risks raised by data collection from service providers in the Semantic Web of Things.
Data producers specify by a set of privacy queries the data they do not want to be disclosed and service providers make explicit by a set utility queries the data 
they request to each data producer for offering them services in return. 

The user interface provides several types of support to data producers. First, it presents in an interpretable form the requests of a service provider for utility purpose. 
Second, it provides a form-based interface for guiding data producers in construction of privacy queries. Third, it detects the privacy risks and provides a factual 
explanation for each detected privacy risk. Last, it provides several options for modifying the utility queries to reduce the detected privacy risks. 

PrivEx is implemented using python 3.9.6. To run it on your system you need to install python and download all the files included in its directory.
Run "UI.py" file to access and use the interactive user interface.

The following files are included in the directory of PrivEx:
- UQs.text:The textual description of utility queries that are entered in UQs.sparql file is provided in this file.
- UQs.sparql: The utility queries in SPARQL-like syntax are provided in this file.
- PQs.text: The textual description of privacy queries that are entered in PQs.sparql file is provided in this file.
- PQs.sparql: The privacy queries in SPARQL-like syntax are provided in this file.
- UI.py file: Contains the code for the user interface and the several types of support it provides.
- compatibilityChecking.py: Contains code implemented for the detection and explanation of privacy risks. On the basis of explanation of detected privcay risks it also 
produce suggestions for reducing the privcay risks. The "UI.py" file uses the output from this file to explain the detected privacy risks and to provide several options 
for the negotiation to reduce the detected privacy risks.
- TACQ.py: Code impelmented for storing and manipulating the utility and privacy queries provided in UQs.sparql file and PQs.sparql file.
- issda_schema.ttl: It is a simple RDFS ontology designed to provide a shared vocabulary used by service providers to express their utility queries and by data producers
to express their privacy queries. It is used in the implementation of the user interface designed for guiding the data producers in the construction of privacy queries.
- Img-SC.jpg: It is an image file used in the explanation of a privacy risk. 

