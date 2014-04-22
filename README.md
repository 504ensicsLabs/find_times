find_times
==========

Discover potential timestamps within the Windows Registry


  Many programs and actions save timestamps within the Windows Registry for their own personal use. We wanted a way to discover as many of these timestamps as possible in the event that they could prove interesting or useful to forensic efforts. This script attempts to perform a bruteforce conversion of data in the registry into many of the different accepted timestamp formats that exist. If the data appears to convert properly, we then perform a variety of sanity checks on it to reduce the vast number of false positives resulting from the bruteforce techniques. A simple example may be that we discard all timestamps occuring before the Windows installation date. We may also apply a filter range to further reduce the results.
  
  To contribute to the results, please use this google docs spreadsheet so we can organize our efforts:  
  <a href="https://docs.google.com/spreadsheets/d/1Tcj0ucpDJcTbh-YFs2r-P2u00eeEu0AdqGfe_Lj0qbU/edit?usp=sharing">Collaborative Results</a>

###Dependencies:
  * pyregf

###Developers:
  * Andrew Case
  * Jerry Stormo
  * Joseph Sylve
  * Vico Marziale
  
Copyright (C) 504ENSICS Labs 2014  
www.504ENSICS.com
