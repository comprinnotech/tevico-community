import { ChartProps } from "@/components/tevico/charts";
import { StatsProps } from "@/components/tevico/statsWithChart";
// import { TableProps } from "@/components/tevico/table";
import { Report } from "@/components/tevico/types/analyticsTypes";

interface ChartParams {
  reports: Report[];
  checkStatus: 'failed' | 'passed';
  statusBy: 'service' | 'section' | 'severity';
  isDonut?: boolean;
}

export function getProgressProps({
  reports,
  checkStatus,
  statusBy
}: ChartParams): StatsProps {
  return {
    cardTitle: `By ${statusBy.charAt(0).toUpperCase() + statusBy.slice(1)}`,
    cardType: checkStatus === "failed" ? "Error" : "Success",
    chartData: reports
      .map((report) => {
        return {
          title: report.name,
          value:
            (report.check_status[checkStatus] / report.check_status.total) * 100,
          label: `${((report.check_status[checkStatus] / report.check_status.total) * 100).toFixed(2)}%`,
        };
      })
      .filter((severity) => severity.value > 0),
    footerData: reports
      .map((severity) => {
        return {
          title: severity.name
            .split(" ")
            .map(
              (word) =>
                word.charAt(0).toUpperCase() + word.slice(1).toLowerCase(),
            )
            .join(" "),
          value: severity.check_status[checkStatus],
          unit: `out of ${severity.check_status.total}`,
        };
      })
      .filter((severity) => severity.value > 0),
  };
}

export function getPieChartProps({
  reports,
  checkStatus,
  statusBy,
  isDonut = true,
}: ChartParams): ChartProps {

  const data = {
    data: reports
      .sort((a, b) => b.check_status[checkStatus] - a.check_status[checkStatus])
      .slice(0, 5)
      .reduce((acc: {[key:string]: number}, service: Report) => {
        if (!acc[service.name]) {
          acc[service.name] = 0;
        }
        acc[service.name] += service.check_status[checkStatus];
        return acc;
      }, {}),
    config: {
      labelKey: statusBy,
      valueKey: "checks",
      titleKey: "Checks",
    },
  };

  const props: ChartProps = {
    type: isDonut === true ? "PIE_WITH_STATS" : "PIE",
    cardTitle: `By ${statusBy.charAt(0).toUpperCase() + statusBy.slice(1)}`,
    cardType: checkStatus === "failed" ? "Error" : "Success",
  };

  if (isDonut) {
    props.pieChartWithStatsData = data;
  } else {
    props.pieChartData = data;
  }

  return props;
}

// interface TableParams {
//   reports: CheckReport[];
//   checkStatus: 'failed' | 'passed';
// }

// export function getTableProps({
//   reports,
//   checkStatus,
// }: TableParams): TableProps {
//   return {
//     tableData: reports.filter((report) => report.check_status[checkStatus] > 0),
//   };
// }
