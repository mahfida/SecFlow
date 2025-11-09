library(ggplot2)
library(reshape2)
# Tree 1:
ben<-c(1050, 83, 80, 20, 1030)
tcp<-c(3892, 2315, 210, 2405,1487)
ack<-c(5289,2815,310,3198,2091)
rst<-c(8287,5812,312,6193,2094)
syn<-c(11274,7490,332,9070,2204)
syn<-syn-rst
rst<-rst-ack
ack<-ack-tcp
tcp<-tcp-ben
bening_pkts <- c(ben[5]/ben[1],tcp[5]/tcp[1],ack[5]/ack[1],rst[5]/rst[1],syn[5]/syn[1])
attack_pkts <- c(ben[4]/ben[1],tcp[4]/tcp[1],ack[4]/ack[1],rst[4]/rst[1],syn[4]/syn[1])
attack_flows <-c((ben[2]-ben[3])/ben[2],
                 (tcp[2]-tcp[3])/tcp[2],
                 (ack[2]-ack[3])/ack[2],
                 (rst[2]-rst[3])/rst[2],
                 (syn[2]-syn[3])/syn[2])
# Trees 3:
# ben, tcp, ack, rst, syn: 
bening_pkts3 <-c(0.965,0.20,0.46,0.01,0.01)
attack_flows3<-c(0.036,0.95,0.827,0.998,0.995)

# Trees 5:
bening_pkts5 <-c(0.967,0.21,0.44,0.01,0.01)
attack_pkts5 <-c(0.032,0.794, 0.56, 0.99,0.99)
attack_flows5<-c(0.061, 0.95,0.828,0.998, .996)


allcolors = c("firebrick3","darkgreen","blue","purple","lavenderblush4")
allborders= c("lightpink", "#b9e38d", "#a1e9f0", "#d9b1f0","white")
## DRAW ############
par(mfrow = c(1,2), cex.lab=1.1,cex=1.1, 
    mar=c(5.5,5,2,0.5), mgp=c(2.5,0.5,0), family="Times")

# library
library(ggplot2)

# create a dataset
Flows <- c(rep("Benign",2) , rep("TCP Flood",2) , rep("ACK Frag.",2), rep("RSTFIN Flood",2),
           rep("SYN Flood",2))
Packets<- rep(c("Attack","Benign") , 5)

Percentage <- c(attack_pkts[1],bening_pkts[1],
                attack_pkts[2],bening_pkts[2],
                attack_pkts[3],bening_pkts[3],
                attack_pkts[4],bening_pkts[4],
                attack_pkts[5],bening_pkts[5])
data1 <- data.frame(Flows,Packets,Percentage)

Attack_flows <-c(attack_flows*100)
Flow_type=c("Benign","TCP Flood","ACK Frag","RSTFIN Flood","SYN Flood")
df <- data.frame(Flow_type, Attack_flows)
# Stacked
p1<-ggplot(data1, aes(fill=Packets, y=Percentage, x=factor(Flows, level=c("Benign","ACK Frag.","TCP Flood","SYN Flood","RSTFIN Flood")))) + 
  geom_bar(position="stack", stat="identity")+
  scale_fill_manual(values=c("coral2","forestgreen"))+theme_classic() + theme(legend.position="top")+
  labs(y= "Percentage", x = "Flow Type\n(a)")+
  theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust=1))
# Basic barplot
# p2<-ggplot(data=df, aes(x=Flow_type, y=Attack_flows)) +
#   geom_bar(stat="identity", fill=c("slategray1"))+theme_classic()+
#   labs(y= "Percentage of detected \nAttack flows", x = "Flows Type\n(b)")+
#   theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust=1))

Names=c("Benign","TCP Flood","ACK Frag.","RSTFIN Flood","SYN Flood")
data2=data.frame(cbind(attack_flows*100,attack_flows3*100,attack_flows5*100),Names)   # combine them into a data frame
# melt the data frame for plotting
data.m <- melt(data2, id.vars='Names')

# plot everything
p2<-ggplot(data.m, aes(x=factor(Names, level=c("Benign","ACK Frag.","TCP Flood","SYN Flood","RSTFIN Flood")), value)) +   
  geom_bar(aes(fill = variable), position = "dodge", stat="identity")+
  xlab("Flow Type\n(b)") +
  ylab("Percentage of detected \nAttack flows")+
  scale_fill_manual("RF Trees",labels=c(1,2,3), values=c("powderblue","steelblue2","royalblue1"))+
  theme_minimal() +
  theme(panel.grid.minor.x = element_blank())+
  theme(legend.position='top')+
  theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust=1))

require(gridExtra)
grid.arrange(p1, p2, ncol=2)


# boxplot(x ~ z + y, data = DF2,
#         at = c(1:2, 4:5, 7:8, 10:11),
#         ylab="% age Accuracy",
#         xlab="RF Tree depth",
#         xaxt='n',
#         yaxt="n",
#         col = rep(allcolors,4), 
#         border=rep(allborders,4),
#         horiz = FALSE, outline=FALSE)
# axis(side=2, las=2)





