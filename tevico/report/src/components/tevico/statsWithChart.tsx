import React from "react";

import { Bar, BarChart, LabelList, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "../ui/card";
import { Separator } from "../ui/separator";
import { generateChartColor } from "./charts";

type ChartData = {
  title: string;
  value: number;
  label: string;
  fill?: string;
};

type FooterData = {
  title: string;
  value: number | string;
  unit: string;
};

export interface StatsProps {
  cardTitle?: string;
  footerData: FooterData[];
  chartData: ChartData[];
  cardType?: string;
}

export function StatsWithChart({ footerData, chartData, cardTitle, cardType }: StatsProps) {

  const style: React.CSSProperties = {};

  if (cardType === 'Error') {
    style.backgroundColor = 'rgba(255, 0, 0, 0.05)';
  } else if (cardType === 'Success') {
    style.backgroundColor = 'rgba(0, 255, 0, 0.05)';
  }

  const coloredChartData = chartData.map((data, index) => ({
    ...data,
    fill: `hsl(var(--chart-${index + 1}))` || generateChartColor(),
  }));
  return (
    <Card className="flex flex-col" style={style}>
      <CardHeader>
        {cardTitle && (<CardTitle>{cardTitle}</CardTitle>)}
      </CardHeader>
      <CardContent className="flex-1 flex justify-center items-center gap-4 p-4 pb-2">
        <BarChart width={500} height={200}
          margin={{
            left: 10,
            right: 0,
            top: 0,
            bottom: 10,
          }}
          data={coloredChartData}
          layout="vertical"
          barSize={32}
          barGap={2}
        >
          <XAxis type="number" dataKey="value" hide />
          <YAxis
            dataKey="title"
            type="category"
            tickLine={false}
            tickMargin={4}
            axisLine={false}
            className="capitalize"
          />
          <Bar dataKey="value" radius={5}>
            <LabelList
              position="insideLeft"
              dataKey="label"
              fill="white"
              offset={8}
              fontSize={14}
              fontWeight={600}
            />
          </Bar>
        </BarChart>
      </CardContent>
      <CardFooter className="flex flex-row border-t p-4">
        <div className="flex w-full items-center gap-2">
          <div className="flex w-full items-center gap-2">
            {footerData.map((item, index) => (
              <React.Fragment key={`fragment-${item.title}-${index}`}>
                <div className="grid flex-1 auto-rows-min gap-0.5">
                  <div className="text-xs text-muted-foreground">{item.title}</div>
                  <div className="flex items-baseline gap-1 text-2xl font-bold tabular-nums leading-none">
                    {item.value}
                    <span className="text-sm font-normal text-muted-foreground">
                      {item.unit}
                    </span>
                  </div>
                </div>
                {index !== footerData.length - 1 && (
                  <Separator orientation="vertical" className="mx-2 h-10 w-px" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      </CardFooter>
    </Card>
  )
}