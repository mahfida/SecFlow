# Load required libraries
library(ggplot2)
library(reshape2)
library(pROC)

# Read CSV
metrics <- read.csv("C:\\Users\\MRAdmin\\Downloads\\Research\\P4-secFlow\\pythonscripts\\comparitiveresults.csv")
p_metrics<-metrics[metrics$Traffic.1=='p',]
f_metrics<-metrics[metrics$Traffic.1=='f',]

#F1 score, Precision and Recall----
p_tcp_metric<-p_metrics[p_metrics$Type=='tcp',]
p_udp_metric<-p_metrics[p_metrics$Type=='udp',]

# TCP packet dataset=====================================================
# Inspect the data- CT ----------------
ct.p.tcp.TP = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$CT)
ct.p.tcp.FP = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$CT)
ct.p.tcp.TN = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$Total)-ct.p.tcp.FP
ct.p.tcp.FN = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$Total)-ct.p.tcp.TP
ct.p.tcp.recall = ct.p.tcp.sensitivity = ct.p.tcp.TP/(ct.p.tcp.TP+ct.p.tcp.FN) # recall/TPR
ct.p.tcp.specificity = ct.p.tcp.TN/(ct.p.tcp.TN+ct.p.tcp.FP) # TNR
ct.p.tcp.precision = ct.p.tcp.TP/(ct.p.tcp.TP+ct.p.tcp.FP)
ct.p.tcp.f1= 2*(ct.p.tcp.precision*ct.p.tcp.recall)/(ct.p.tcp.precision+ct.p.tcp.recall)

# Inspect the data - C-----------------
c.p.tcp.TP = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$C)
c.p.tcp.FP = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$C)
c.p.tcp.TN = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$Total)-c.p.tcp.FP
c.p.tcp.FN = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$Total)-c.p.tcp.TP
c.p.tcp.recall = c.p.tcp.sensitivity = c.p.tcp.TP/(c.p.tcp.TP+c.p.tcp.FN) # recall/TPR
c.p.tcp.specificity = c.p.tcp.TN/(c.p.tcp.TN+c.p.tcp.FP) # TNR
c.p.tcp.precision = c.p.tcp.TP/(c.p.tcp.TP+c.p.tcp.FP)
c.p.tcp.f1= 2*(c.p.tcp.precision*c.p.tcp.recall)/(c.p.tcp.precision+c.p.tcp.recall)

# Inspect the data- ST ----------------
st.p.tcp.TP = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$ST)
st.p.tcp.FP = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$ST)
st.p.tcp.TN = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$Total)-st.p.tcp.FP
st.p.tcp.FN = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$Total)-st.p.tcp.TP
st.p.tcp.recall = st.p.tcp.sensitivity = st.p.tcp.TP/(st.p.tcp.TP+st.p.tcp.FN) # recall/TPR
st.p.tcp.specificity = st.p.tcp.TN/(st.p.tcp.TN+st.p.tcp.FP) # TNR
st.p.tcp.precision = st.p.tcp.TP/(st.p.tcp.TP+st.p.tcp.FP)
st.p.tcp.f1= 2*(st.p.tcp.precision*st.p.tcp.recall)/(st.p.tcp.precision+st.p.tcp.recall)

# Inspect the data - S-----------------
s.p.tcp.TP = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$S)
s.p.tcp.FP = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$S)
s.p.tcp.TN = sum(p_tcp_metric[p_tcp_metric$Traffic=='Benign',]$Total)-s.p.tcp.FP
s.p.tcp.FN = sum(p_tcp_metric[p_tcp_metric$Traffic!='Benign',]$Total)-s.p.tcp.TP
s.p.tcp.recall = s.p.tcp.sensitivity = s.p.tcp.TP/(s.p.tcp.TP+s.p.tcp.FN) # recall/TPR
s.p.tcp.specificity = s.p.tcp.TN/(s.p.tcp.TN+s.p.tcp.FP) # TNR
s.p.tcp.precision = s.p.tcp.TP/(s.p.tcp.TP+s.p.tcp.FP)
s.p.tcp.f1= 2*(s.p.tcp.precision*s.p.tcp.recall)/(s.p.tcp.precision+s.p.tcp.recall)


# udp packet dataset=====================================================
ct.p.udp.TP = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$CT)
ct.p.udp.FP = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$CT)
ct.p.udp.TN = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$Total)-ct.p.udp.FP
ct.p.udp.FN = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$Total)-ct.p.udp.TP
ct.p.udp.recall = ct.p.udp.sensitivity = ct.p.udp.TP/(ct.p.udp.TP+ct.p.udp.FN) # recall/TPR
ct.p.udp.specificity = ct.p.udp.TN/(ct.p.udp.TN+ct.p.udp.FP) # TNR
ct.p.udp.precision = ct.p.udp.TP/(ct.p.udp.TP+ct.p.udp.FP)
ct.p.udp.f1= 2*(ct.p.udp.precision*ct.p.udp.recall)/(ct.p.udp.precision+ct.p.udp.recall)

# Inspect the data - C-----------------
c.p.udp.TP = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$C)
c.p.udp.FP = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$C)
c.p.udp.TN = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$Total)-c.p.udp.FP
c.p.udp.FN = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$Total)-c.p.udp.TP
c.p.udp.recall = c.p.udp.sensitivity = c.p.udp.TP/(c.p.udp.TP+c.p.udp.FN) # recall/TPR
c.p.udp.specificity = c.p.udp.TN/(c.p.udp.TN+c.p.udp.FP) # TNR
c.p.udp.precision = c.p.udp.TP/(c.p.udp.TP+c.p.udp.FP)
c.p.udp.f1= 2*(c.p.udp.precision*c.p.udp.recall)/(c.p.udp.precision+c.p.udp.recall)

# Inspect the data- ST ----------------
st.p.udp.TP = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$ST)
st.p.udp.FP = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$ST)
st.p.udp.TN = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$Total)-st.p.udp.FP
st.p.udp.FN = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$Total)-st.p.udp.TP
st.p.udp.recall = st.p.udp.sensitivity = st.p.udp.TP/(st.p.udp.TP+st.p.udp.FN) # recall/TPR
st.p.udp.specificity = st.p.udp.TN/(st.p.udp.TN+st.p.udp.FP) # TNR
st.p.udp.precision = st.p.udp.TP/(st.p.udp.TP+st.p.udp.FP)
st.p.udp.f1= 2*(st.p.udp.precision*st.p.udp.recall)/(st.p.udp.precision+st.p.udp.recall)

# Inspect the data - S-----------------
s.p.udp.TP = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$S)
s.p.udp.FP = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$S)
s.p.udp.TN = sum(p_udp_metric[p_udp_metric$Traffic=='Benign',]$Total)-s.p.udp.FP
s.p.udp.FN = sum(p_udp_metric[p_udp_metric$Traffic!='Benign',]$Total)-s.p.udp.TP
s.p.udp.recall = s.p.udp.sensitivity = s.p.udp.TP/(s.p.udp.TP+s.p.udp.FN) # recall/TPR
s.p.udp.specificity = s.p.udp.TN/(s.p.udp.TN+s.p.udp.FP) # TNR
s.p.udp.precision = s.p.udp.TP/(s.p.udp.TP+s.p.udp.FP)
s.p.udp.f1= 2*(s.p.udp.precision*s.p.udp.recall)/(s.p.udp.precision+s.p.udp.recall)

## COMPARITIVE RESULTS IN BAR CHART FORM =======================================
# Load libraries
library(ggplot2)   # Not strictly needed for base barplot, but keeping if needed later
library(reshape2)

# --- Prepare metrics data ---
tcp_metrics <- data.frame(
  TrafficType = c("TCP1","TCP2"),   # Placeholder, will use expression() later
  Precision   = c(ct.p.tcp.precision, c.p.tcp.precision),
  Recall      = c(ct.p.tcp.recall, c.p.tcp.recall),
  F1          = c(ct.p.tcp.f1, c.p.tcp.f1)
)

udp_metrics <- data.frame(
  TrafficType = c("UDP1","UDP2"),
  Precision   = c(ct.p.udp.precision, c.p.udp.precision),
  Recall      = c(ct.p.udp.recall, c.p.udp.recall),
  F1          = c(ct.p.udp.f1, c.p.udp.f1)
)

# --- Set up side by side plotting ----------------
#==================================================

# Set layout for 2 side-by-side plots and give space for common legend
par(mfrow=c(1,2), mar=c(6,5,2,2), oma=c(4,0,0,0))  # oma = outer margins

# TCP Plot
bp_tcp <- barplot(
  t(as.matrix(tcp_metrics[,2:4])),
  beside=TRUE,
  names.arg=c(expression(D[w]), expression(D[wo])),
  col=c("#E41A1C","#4DAF4A","#377EB8"),
  density=c(20,40,60),
  angle=c(45,135,0),
  ylim=c(0,1),
  ylab="Score",
  cex.names=1.3,
  cex.lab=1.3,
  cex.axis=1.3,
  las=1
)
mtext("(a) TCP Packets", side=1, line=4, cex=1.3)

# UDP Plot
bp_udp <- barplot(
  t(as.matrix(udp_metrics[,2:4])),
  beside=TRUE,
  names.arg=c(expression(D[w]), expression(D[wo])),
  col=c("#E41A1C","#4DAF4A","#377EB8"),
  density=c(20,40,60),
  angle=c(45,135,0),
  ylim=c(0,1),
  ylab="Score",
  cex.names=1.3,
  cex.lab=1.3,
  cex.axis=1.3,
  las=1
)
mtext("(b) UDP Packets", side=1, line=4, cex=1.3)
par(mfrow=c(1,1), oma=c(0,0,0,0), xpd=FALSE)

# Add one common legend below both plots
par(xpd=NA)  # allow drawing outside plot region
legend("bottom",
       inset=-0.5,    # push legend below the plots
       xpd=NA,         # allow outside margins
       legend=c("Precision","Recall","F1"),
       fill=c("#E41A1C","#4DAF4A","#377EB8"),
       density=c(20,40,60), angle=c(45,135,0),
       horiz=TRUE, cex=1.2, bty="n")

## COMPARITIVE RESULTS IN BAR CHART FORM =======================================
# Load libraries
library(ggplot2)   # Not strictly needed for base barplot, but keeping if needed later
library(reshape2)

# --- Prepare metrics data ---
tcp_metrics <- data.frame(
  TrafficType = c("TCP1","TCP2"),
  TPR   = c(ct.p.tcp.specificity, c.p.tcp.specificity),
  TNR      = c(ct.p.tcp.recall,    c.p.tcp.recall),
  F1          = c(ct.p.tcp.f1,        c.p.tcp.f1)
)

udp_metrics <- data.frame(
  TrafficType = c("UDP1","UDP2"),
  TPR   = c(ct.p.udp.specificity, c.p.udp.specificity),
  TNR      = c(ct.p.udp.recall,    c.p.udp.recall),
  F1          = c(ct.p.udp.f1,        c.p.udp.f1)
)

# --- Set up side-by-side plotting with space for shared legend ---
par(mfrow = c(1, 2),
    mar   = c(6, 5, 2, 2),   # more left margin for larger y-axis text
    oma   = c(4, 0, 0, 0))   # outer margin at bottom for the shared legend

# TCP Plot
bp_tcp <- barplot(
  t(as.matrix(tcp_metrics[, 2:4])),
  beside     = TRUE,
  names.arg  = c(expression(D[w]), expression(D[wo])),
  col        = c("#E41A1C","#4DAF4A","#377EB8"),
  density    = c(20,40,60),
  angle      = c(45,135,0),
  ylim       = c(0, 1),
  ylab       = "Score",
  cex.names  = 1.3,   # larger x tick labels
  cex.lab    = 1.3,   # larger axis titles
  cex.axis   = 1.3,   # larger tick labels
  las        = 1      # horizontal y-axis tick labels
)
  mtext("(a) TCP Packets", side = 1, line = 4, cex = 1.3)

# UDP Plot
bp_udp <- barplot(
  t(as.matrix(udp_metrics[, 2:4])),
  beside     = TRUE,
  names.arg  = c(expression(D[w]), expression(D[wo])),
  col        = c("#E41A1C","#4DAF4A","#377EB8"),
  density    = c(20,40,60),
  angle      = c(45,135,0),
  ylim       = c(0, 1),
  ylab       = "Score",
  cex.names  = 1.3,
  cex.lab    = 1.3,
  cex.axis   = 1.3,
  las        = 1
)
mtext("(b) UDP Packets", side = 1, line = 4, cex = 1.3)
# Reset
par(mfrow = c(1, 1), oma = c(0, 0, 0, 0), xpd = FALSE)
# --- One shared legend centered below both plots ---
par(xpd = NA)  # allow drawing in the outer margin
legend("bottom",
       inset  = -0.5,  # push legend into the outer bottom margin
       xpd    = NA,
       legend = c("TPR", "TNR", "F1"),
       fill   = c("#E41A1C","#4DAF4A","#377EB8"),
       density= c(20,40,60),
       angle  = c(45,135,0),
       horiz  = TRUE,
       cex    = 1.2,
       bty    = "n")


######Do Same for Flows ###########################
#F1 score, Precision and Recall----
f_tcp_metric<-f_metrics[f_metrics$Type=='tcp',]
f_udp_metric<-f_metrics[f_metrics$Type=='udp',]

# TCP packet dataset=====================================================
# Inspect the data- CT ----------------
ct.f.tcp.TP = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$CT)
ct.f.tcp.FP = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$CT)
ct.f.tcp.TN = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$Total)-ct.f.tcp.FP
ct.f.tcp.FN = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$Total)-ct.f.tcp.TP
ct.f.tcp.recall = ct.f.tcp.sensitivity = ct.f.tcp.TP/(ct.f.tcp.TP+ct.f.tcp.FN) # recall/TPR
ct.f.tcp.specificity = ct.f.tcp.TN/(ct.f.tcp.TN+ct.f.tcp.FP) # TNR
ct.f.tcp.precision = ct.f.tcp.TP/(ct.f.tcp.TP+ct.f.tcp.FP)
ct.f.tcp.f1= 2*(ct.f.tcp.precision*ct.f.tcp.recall)/(ct.f.tcp.precision+ct.f.tcp.recall)

# Inspect the data - C-----------------
c.f.tcp.TP = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$C)
c.f.tcp.FP = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$C)
c.f.tcp.TN = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$Total)-c.f.tcp.FP
c.f.tcp.FN = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$Total)-c.f.tcp.TP
c.f.tcp.recall = c.f.tcp.sensitivity = c.f.tcp.TP/(c.f.tcp.TP+c.f.tcp.FN) # recall/TPR
c.f.tcp.specificity = c.f.tcp.TN/(c.f.tcp.TN+c.f.tcp.FP) # TNR
c.f.tcp.precision = c.f.tcp.TP/(c.f.tcp.TP+c.f.tcp.FP)
c.f.tcp.f1= 2*(c.f.tcp.precision*c.f.tcp.recall)/(c.f.tcp.precision+c.f.tcp.recall)

# Inspect the data- ST ----------------
st.f.tcp.TP = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$ST)
st.f.tcp.FP = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$ST)
st.f.tcp.TN = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$Total)-st.f.tcp.FP
st.f.tcp.FN = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$Total)-st.f.tcp.TP
st.f.tcp.recall = st.f.tcp.sensitivity = st.f.tcp.TP/(st.f.tcp.TP+st.f.tcp.FN) # recall/TPR
st.f.tcp.specificity = st.f.tcp.TN/(st.f.tcp.TN+st.f.tcp.FP) # TNR
st.f.tcp.precision = st.f.tcp.TP/(st.f.tcp.TP+st.f.tcp.FP)
st.f.tcp.f1= 2*(st.f.tcp.precision*st.f.tcp.recall)/(st.f.tcp.precision+st.f.tcp.recall)

# Inspect the data - S-----------------
s.f.tcp.TP = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$S)
s.f.tcp.FP = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$S)
s.f.tcp.TN = sum(f_tcp_metric[f_tcp_metric$Traffic=='Benign',]$Total)-s.f.tcp.FP
s.f.tcp.FN = sum(f_tcp_metric[f_tcp_metric$Traffic!='Benign',]$Total)-s.f.tcp.TP
s.f.tcp.recall = s.f.tcp.sensitivity = s.f.tcp.TP/(s.f.tcp.TP+s.f.tcp.FN) # recall/TPR
s.f.tcp.specificity = s.f.tcp.TN/(s.f.tcp.TN+s.f.tcp.FP) # TNR
s.f.tcp.precision = s.f.tcp.TP/(s.f.tcp.TP+s.f.tcp.FP)
s.f.tcp.f1= 2*(s.f.tcp.precision*s.f.tcp.recall)/(s.f.tcp.precision+s.f.tcp.recall)


# udp packet dataset=====================================================
ct.f.udp.TP = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$CT)
ct.f.udp.FP = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$CT)
ct.f.udp.TN = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$Total)-ct.f.udp.FP
ct.f.udp.FN = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$Total)-ct.f.udp.TP
ct.f.udp.recall = ct.f.udp.sensitivity = ct.f.udp.TP/(ct.f.udp.TP+ct.f.udp.FN) # recall/TPR
ct.f.udp.specificity = ct.f.udp.TN/(ct.f.udp.TN+ct.f.udp.FP) # TNR
ct.f.udp.precision = ct.f.udp.TP/(ct.f.udp.TP+ct.f.udp.FP)
ct.f.udp.f1= 2*(ct.f.udp.precision*ct.f.udp.recall)/(ct.f.udp.precision+ct.f.udp.recall)

# Inspect the data - C-----------------
c.f.udp.TP = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$C)
c.f.udp.FP = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$C)
c.f.udp.TN = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$Total)-c.f.udp.FP
c.f.udp.FN = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$Total)-c.f.udp.TP
c.f.udp.recall = c.f.udp.sensitivity = c.f.udp.TP/(c.f.udp.TP+c.f.udp.FN) # recall/TPR
c.f.udp.specificity = c.f.udp.TN/(c.f.udp.TN+c.f.udp.FP) # TNR
c.f.udp.precision = c.f.udp.TP/(c.f.udp.TP+c.f.udp.FP)
c.f.udp.f1= 2*(c.f.udp.precision*c.f.udp.recall)/(c.f.udp.precision+c.f.udp.recall)

# Inspect the data- ST ----------------
st.f.udp.TP = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$ST)
st.f.udp.FP = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$ST)
st.f.udp.TN = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$Total)-st.f.udp.FP
st.f.udp.FN = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$Total)-st.f.udp.TP
st.f.udp.recall = st.f.udp.sensitivity = st.f.udp.TP/(st.f.udp.TP+st.f.udp.FN) # recall/TPR
st.f.udp.specificity = st.f.udp.TN/(st.f.udp.TN+st.f.udp.FP) # TNR
st.f.udp.precision = st.f.udp.TP/(st.f.udp.TP+st.f.udp.FP)
st.f.udp.f1= 2*(st.f.udp.precision*st.f.udp.recall)/(st.f.udp.precision+st.f.udp.recall)

# Inspect the data - S-----------------
s.f.udp.TP = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$S)
s.f.udp.FP = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$S)
s.f.udp.TN = sum(f_udp_metric[f_udp_metric$Traffic=='Benign',]$Total)-s.f.udp.FP
s.f.udp.FN = sum(f_udp_metric[f_udp_metric$Traffic!='Benign',]$Total)-s.f.udp.TP
s.f.udp.recall = s.f.udp.sensitivity = s.f.udp.TP/(s.f.udp.TP+s.f.udp.FN) # recall/TPR
s.f.udp.specificity = s.f.udp.TN/(s.f.udp.TN+s.f.udp.FP) # TNR
s.f.udp.precision = s.f.udp.TP/(s.f.udp.TP+s.f.udp.FP)
s.f.udp.f1= 2*(s.f.udp.precision*s.f.udp.recall)/(s.f.udp.precision+s.f.udp.recall)

## COMPARITIVE RESULTS IN BAR CHART FORM =======================================
# Load libraries
library(ggplot2)   # Not strictly needed for base barplot, but keeping if needed later
library(reshape2)

# --- Prepare metrics data ---
tcp_metrics <- data.frame(
  TrafficType = c("TCP1","TCP2"),
  Precision   = c(ct.f.tcp.precision, c.f.tcp.precision),
  Recall      = c(ct.f.tcp.recall,    c.f.tcp.recall),
  F1          = c(ct.f.tcp.f1,        c.f.tcp.f1)
)

udp_metrics <- data.frame(
  TrafficType = c("UDP1","UDP2"),
  Precision   = c(ct.f.udp.precision, c.f.udp.precision),
  Recall      = c(ct.f.udp.recall,    c.f.udp.recall),
  F1          = c(ct.f.udp.f1,        c.f.udp.f1)
)

# --- Set up side-by-side plotting with space for shared legend ---
par(mfrow = c(1, 2),
    mar   = c(6, 5, 2, 2),   # more left margin for larger y-axis text
    oma   = c(4, 0, 0, 0))   # outer margin at bottom for the shared legend

# TCP Plot
bp_tcp <- barplot(
  t(as.matrix(tcp_metrics[, 2:4])),
  beside     = TRUE,
  names.arg  = c(expression(D[w]), expression(D[wo])),
  col        = c("#E41A1C","#4DAF4A","#377EB8"),
  density    = c(20,40,60),
  angle      = c(45,135,0),
  ylim       = c(0, 1),
  ylab       = "Score",
  cex.names  = 1.3,   # larger x tick labels
  cex.lab    = 1.3,   # larger axis titles
  cex.axis   = 1.3,   # larger tick labels
  las        = 1      # horizontal y-axis tick labels
)
mtext("(a) TCP Flows", side = 1, line = 4, cex = 1.3)

# UDP Plot
bp_udp <- barplot(
  t(as.matrix(udp_metrics[, 2:4])),
  beside     = TRUE,
  names.arg  = c(expression(D[w]), expression(D[wo])),
  col        = c("#E41A1C","#4DAF4A","#377EB8"),
  density    = c(20,40,60),
  angle      = c(45,135,0),
  ylim       = c(0, 1),
  ylab       = "Score",
  cex.names  = 1.3,
  cex.lab    = 1.3,
  cex.axis   = 1.3,
  las        = 1
)
mtext("(b) UDP Flows", side = 1, line = 4, cex = 1.3)
# Reset
par(mfrow = c(1, 1), oma = c(0, 0, 0, 0), xpd = FALSE)
# --- One shared legend centered below both plots ---
par(xpd = NA)  # allow drawing in the outer margin
legend("bottom",
       inset  = -0.5,  # push legend into the outer bottom margin
       xpd    = NA,
       legend = c("Precision", "Recall", "F1"),
       fill   = c("#E41A1C","#4DAF4A","#377EB8"),
       density= c(20,40,60),
       angle  = c(45,135,0),
       horiz  = TRUE,
       cex    = 1.2,
       bty    = "n")


## COMPARITIVE RESULTS IN BAR CHART FORM =======================================
# Load libraries
library(ggplot2)   # Not strictly needed for base barplot, but keeping if needed later
library(reshape2)

# --- Prepare metrics data ---
tcp_metrics <- data.frame(
  TrafficType = c("TCP1","TCP2"),
  TPR   = c(ct.f.tcp.specificity, c.f.tcp.specificity),
  TNR      = c(ct.f.tcp.recall,    c.f.tcp.recall),
  F1          = c(ct.f.tcp.f1,        c.f.tcp.f1)
)

udp_metrics <- data.frame(
  TrafficType = c("UDP1","UDP2"),
  TPR   = c(ct.f.udp.specificity, c.f.udp.specificity),
  TNR      = c(ct.f.udp.recall,    c.f.udp.recall),
  F1          = c(ct.f.udp.f1,        c.f.udp.f1)
)

# --- Set up side-by-side plotting with space for shared legend ---
par(mfrow = c(1, 2),
    mar   = c(6, 5, 2, 2),   # more left margin for larger y-axis text
    oma   = c(4, 0, 0, 0))   # outer margin at bottom for the shared legend

# TCP Plot
bp_tcp <- barplot(
  t(as.matrix(tcp_metrics[, 2:4])),
  beside     = TRUE,
  names.arg  = c(expression(D[w]), expression(D[wo])),
  col        = c("#E41A1C","#4DAF4A","#377EB8"),
  density    = c(20,40,60),
  angle      = c(45,135,0),
  ylim       = c(0, 1),
  ylab       = "Score",
  cex.names  = 1.3,   # larger x tick labels
  cex.lab    = 1.3,   # larger axis titles
  cex.axis   = 1.3,   # larger tick labels
  las        = 1      # horizontal y-axis tick labels
)
mtext("(a) TCP Flows", side = 1, line = 4, cex = 1.3)

# UDP Plot
bp_udp <- barplot(
  t(as.matrix(udp_metrics[, 2:4])),
  beside     = TRUE,
  names.arg  = c(expression(D[w]), expression(D[wo])),
  col        = c("#E41A1C","#4DAF4A","#377EB8"),
  density    = c(20,40,60),
  angle      = c(45,135,0),
  ylim       = c(0, 1),
  ylab       = "Score",
  cex.names  = 1.3,
  cex.lab    = 1.3,
  cex.axis   = 1.3,
  las        = 1
)
mtext("(b) UDP Flows", side = 1, line = 4, cex = 1.3)
# Reset
par(mfrow = c(1, 1), oma = c(0, 0, 0, 0), xpd = FALSE)
# --- One shared legend centered below both plots ---
par(xpd = NA)  # allow drawing in the outer margin
legend("bottom",
       inset  = -0.5,  # push legend into the outer bottom margin
       xpd    = NA,
       legend = c("TPR", "TNR", "F1"),
       fill   = c("#E41A1C","#4DAF4A","#377EB8"),
       density= c(20,40,60),
       angle  = c(45,135,0),
       horiz  = TRUE,
       cex    = 1.2,
       bty    = "n")
