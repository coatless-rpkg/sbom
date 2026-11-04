library(shiny)
library(DT)
shinyApp(fluidPage(DTOutput("t")), function(input, output, session) {})
