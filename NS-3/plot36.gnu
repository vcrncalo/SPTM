# Setting up the format for the image.
set terminal png
set output 'throughput_bps-average_delay-36.png'

# Setting up the plot.
set grid
set title "Throughput and average delay vs time"
set xlabel "Time (s)"
set ylabel "Throughput (bps)"
set y2label "Average delay (s)"
set y2tics

# Setting a label for the total number of packets.
total_packets = 36 # Za 36 paketa

# Adding the label for the total number of packets.
set label 1 "Total Packets: " . total_packets at graph 0, 0.015 font ",12"

# Plotting throughput and the average delay.
plot "output.txt" using 1:4 with lines title "Throughput (bps)", \
"output.txt" using 1:5 with lines title "Average delay (s)" axes x1y2

