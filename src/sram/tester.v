
`define sb200
`timescale  1ns /  10ps
module tester;
// synthesis translate_off
   reg        wr_0_req;
   reg [18:0] wr_0_addr;
   reg [35:0] wr_0_data;

   reg        rd_0_req;
   reg [18:0] rd_0_addr;
   wire [35:0] rd_0_data;

   wire [35:0] sram_data;
   wire [35:0] sram_wr_data;
   wire [18:0] sram_addr;
   wire [3:0]    sram_bw;

   reg           reset;
   reg           clk;

   sram_arbiter sram_arbiter
        (// --- Requesters   (read and/or write)
         .wr_0_req           (wr_0_req),
         .wr_0_addr          (wr_0_addr),
         .wr_0_data          (wr_0_data),
         .wr_0_ack           (wr_0_ack),

         .rd_0_req           (rd_0_req),
         .rd_0_addr          (rd_0_addr),
         .rd_0_data          (rd_0_data),
         .rd_0_ack           (rd_0_ack),
         .rd_0_vld           (rd_0_vld),

         // --- sram access
         .sram_addr          (sram_addr),
         .sram_wr_data       (sram_wr_data),
         .sram_rd_data       (sram_data),
         .sram_we            (sram_we),
         .sram_bw            (sram_bw),
         .sram_tri_en        (sram_tri_en),

         // --- register interface
         .sram_reg_req       (1'b0),
         .sram_reg_rd_wr_L   (1'b1),
         .sram_reg_addr      (0),
         .sram_reg_wr_data   (0),
         .sram_reg_rd_data   (),
         .sram_reg_ack       (),

         // --- Misc
         .reset              (reset),
         .clk                (clk)
         );

   always #4 clk = !clk;
   initial begin clk = 0; end

   assign       sram_data = sram_tri_en ? sram_wr_data : 36'hz;
   reg          sram_we_del;
   always @* #2 sram_we_del = sram_we;
   reg [3:0]    sram_bw_del;
   always @* #2 sram_bw_del = sram_bw;
   reg [19:0]   sram_addr_del;
   always @* #2 sram_addr_del = sram_addr;

   cy7c1370 sram (
                  .d      (sram_data),
                  .clk    (clk),
                  .a      (sram_addr_del[18:0]),
                  .bws    (sram_bw_del),
                  .we_b   (sram_we_del),
                  .adv_lb (1'b0),
                  .ce1b   (1'b0),
                  .ce2    (1'b1),
                  .ce3b   (1'b0),
                  .oeb    (1'b0),
                  .cenb   (1'b0),
                  .mode   (1'b0)   // dont care cos we dont burst
                  );

   integer      i;
   initial begin
      i = 0;
      wr_0_req =  0;
      wr_0_addr = 0;
      wr_0_data = 0;
      rd_0_req = 0;
      rd_0_addr = 0;
      reset = 1'b1;
      repeat (15) @(posedge clk) begin end
      reset = 0;
      repeat (20) begin
         @(posedge clk) #1 begin
            wr_0_req = 1;
         end
         wait (wr_0_ack);
         #1 wr_0_addr = wr_0_addr + 1'b1;
         wr_0_data = wr_0_data + 1'b1;
      end
      @(posedge clk) begin
         wr_0_req = 0;
      end
      repeat (20) begin
         @(posedge clk) #1 begin
            rd_0_req = 1;
         end
         if (rd_0_ack) begin
	    rd_0_addr = rd_0_addr + 1'b1;
	 end
         if(rd_0_vld) begin
            if(rd_0_data != i) begin
               $display("%t Error: read found %x instead of %x", $time, rd_0_data, i);
            end
            i = i + 1;
         end
      end
   end // initial begin
// synthesis translate_on
endmodule // tester
