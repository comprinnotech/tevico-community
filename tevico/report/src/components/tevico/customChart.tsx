"use client"

import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts"

export const description = "A donut chart"

interface ChartProps {
    chartData: any[]
  }

export function CustomChart(props: ChartProps) {
  return (
        <PieChart width={250} height={300}>
          <Tooltip />
          <Legend />
          <Pie
            data={props.chartData}
            dataKey="visitors"
            nameKey="browser"
            innerRadius={60}
            outerRadius={80}
            label
          >
            {props.chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.fill} />
            ))}
          </Pie>
        </PieChart>
  )
}