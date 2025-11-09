# Load required libraries
library(ggplot2)
library(reshape2)
library(pROC)

# Read CSV
metrics <- read.csv("C:\\Users\\MRAdmin\\Downloads\\Research\\P4-secFlow\\pythonscripts\\comparitiveresults.csv")
p_metrics<-metrics[metrics$Traffic.1=='p',]
f_metrics<-metrics[metrics$Traffic.1=='f',]

#Packets -------------------------------------
p_metric<-p_metrics[p_metrics$Traffic!='Benign',]
f_metric<-f_metrics[f_metrics$Traffic!='Benign',]

#Accuracy -------------------------------------
p_metric.ct<-p_metric$CT/p_metric$Total
f_metric.ct<-f_metric$CT/f_metric$Total
p_metric.c<-p_metric$C/p_metric$Total
f_metric.c<-f_metric$C/f_metric$Total
p_metric.st<-p_metric$ST/p_metric$Total
f_metric.st<-f_metric$ST/f_metric$Total
p_metric.s<-p_metric$S/p_metric$Total
f_metric.s<-f_metric$S/f_metric$Total