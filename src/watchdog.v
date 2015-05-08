///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id$
//
// Module: watchdog.v
// Project: NF2.1 Tunneling OpenFlow Switch
// Author: Tatsuya Yabe <tyabe@stanford.edu>
// Description: 4.3sec timer. Timer works when the register has been set. It is
//              zero'd upon register access. When timer reaches 4.3sec,
//              "table_flush" output-signal will be asserted.
///////////////////////////////////////////////////////////////////////////////

module watchdog
  #(parameter UDP_REG_SRC_WIDTH  = 2)

   (// --- Register interface
    input                              reg_req_in,
    input                              reg_ack_in,
    input                              reg_rd_wr_L_in,
    input  [`UDP_REG_ADDR_WIDTH-1:0]   reg_addr_in,
    input  [`CPCI_NF2_DATA_WIDTH-1:0]  reg_data_in,
    input  [UDP_REG_SRC_WIDTH-1:0]     reg_src_in,

    output                             reg_req_out,
    output                             reg_ack_out,
    output                             reg_rd_wr_L_out,
    output  [`UDP_REG_ADDR_WIDTH-1:0]  reg_addr_out,
    output  [`CPCI_NF2_DATA_WIDTH-1:0] reg_data_out,
    output  [UDP_REG_SRC_WIDTH-1:0]    reg_src_out,

    // --- flush signal output to the target module(s)
    output reg                         table_flush,

    // --- Misc
    input                              clk,
    input                              reset);

   `LOG2_FUNC

   //------------------ Internal Parameters --------------------------
   localparam TIMER_LIMIT = 30'h3fff_ffff;
   //---------------------- Wires/Regs -------------------------------

   wire                  counter_clear;
   wire                  reg_ack_internal;
   wire [31:0]           enable_flag_reg;
   reg                   reg_acc_event;
   reg [29:0]            watchdog_counter;

   //----------------------- Modules ---------------------------------

   generic_regs
     #( .UDP_REG_SRC_WIDTH     (UDP_REG_SRC_WIDTH),
        .TAG                   (`WDT_BLOCK_ADDR),
        .REG_ADDR_WIDTH        (`WDT_REG_ADDR_WIDTH),
        .NUM_COUNTERS          (0),
        .NUM_SOFTWARE_REGS     (1),
        .NUM_HARDWARE_REGS     (1),
        .ACK_UNFOUND_ADDRESSES (0)) generic_regs
       (
        .reg_req_in            (reg_req_in),
        .reg_ack_in            (reg_ack_in),
        .reg_rd_wr_L_in        (reg_rd_wr_L_in),
        .reg_addr_in           (reg_addr_in),
        .reg_data_in           (reg_data_in),
        .reg_src_in            (reg_src_in),

        .reg_req_out           (reg_req_out),
        .reg_ack_out           (reg_ack_internal),
        .reg_rd_wr_L_out       (reg_rd_wr_L_out),
        .reg_addr_out          (reg_addr_out),
        .reg_data_out          (reg_data_out),
        .reg_src_out           (reg_src_out),

        // --- counters interface
        .counter_updates       (1'b0),
        .counter_decrement     (1'b0),

        // --- SW regs interface
        .software_regs         (enable_flag_reg),

        // --- HW regs interface
        .hardware_regs         ({2'b0, watchdog_counter}),

        .clk                   (clk),
        .reset                 (reset));

   //------------------------ Logic ----------------------------------

   assign reg_ack_out   = reg_ack_internal;

   //This process is for reducing load of reg_ack
   always @(posedge clk) begin
      if(reset) begin
         reg_acc_event <= 0;
      end
      else begin
         reg_acc_event <= reg_ack_internal;
      end
   end

   assign counter_clear = !enable_flag_reg[0] || reg_acc_event;

   always @(posedge clk) begin
      if(reset) begin
         watchdog_counter <= 0;
      end
      else begin
         if (counter_clear) begin
            watchdog_counter <= 0;
         end
         else begin
            watchdog_counter <= watchdog_counter + 1;
         end
      end
   end

   always @(posedge clk) begin
      if(reset) begin
         table_flush <= 0;
      end
      else begin
         if (counter_clear) begin
            table_flush <= 0;
         end
         else if (watchdog_counter == TIMER_LIMIT) begin
            table_flush <= 1;
         end
         else begin
            table_flush <= 0;
         end
      end
   end

endmodule
