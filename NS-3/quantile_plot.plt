set terminal png
set output 'quantile_diagram.png'
set title 'Packet Delay Quantile Diagram'
set xlabel 'Quantile'
set ylabel 'Delay (seconds)'
set grid
plot 'quantile_data.dat' using 1:2 with linespoints title 'Packet Delay'
