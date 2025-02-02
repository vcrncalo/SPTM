set terminal png
set output 'quantile_diagram_delay.png'
set title 'Packet Delay Quantile Diagram'
set xlabel 'Quantile'
set ylabel 'Delay (seconds)'
set grid
plot 'quantile_data_delay.dat' using 1:2 with linespoints title 'Packet Delay'

set terminal png
set output 'quantile_diagram_throughput.png'
set title 'Throughput Quantile Diagram'
set xlabel 'Quantile'
set ylabel 'Throughput (bps)'
set grid
plot 'quantile_data_throughput.dat' using 1:2 with linespoints title 'Throughput'
