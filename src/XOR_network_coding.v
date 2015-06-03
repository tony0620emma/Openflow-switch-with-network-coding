///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: XOR_network_coding.v 2015-05-26 $
//
// Module: XOR_network_coding.v
// Project: NF2.1 OpenFlow Switch
// Author: Yan-Hsuan Chuang <tony0620emma@yahoo.com.tw>

// Description: 
//
// Licensing: In addition to the NetFPGA license, the following license applies
//            to the source code in the OpenFlow Switch implementation on NetFPGA.
//
// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
//
// We are making the OpenFlow specification and associated documentation (Software)
// available for public use and benefit with the expectation that others will use,
// modify and enhance the Software and contribute those enhancements back to the
// community. However, since we would like to make the Software available for
// broadest use, with as few restrictions as possible permission is hereby granted,
// free of charge, to any person obtaining a copy of this Software to deal in the
// Software under the copyrights without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// The name and trademarks of copyright holder(s) may NOT be used in advertising
// or publicity pertaining to the Software or any derivatives without specific,
// written prior permission.
///////////////////////////////////////////////////////////////////////////////
`timescale 1ns/1ps

module 
  #(parameter NUM_OUTPUT_QUEUES = 8,
    parameter DATA_WIDTH = 64,
	parameter ADDITIONAL_WORD_CTRL = 8'h42,
    parameter CTRL_WIDTH = DATA_WIDTH/8)
  (// --- interface to opl_processor
   input [DATA_WIDTH-1:0]                  in_data,
   input [CTRL_WIDTH-1:0]                  in_ctrl,
   input                                   in_wr,
  
   // --- interface to output
   output reg [DATA_WIDTH-1:0]             out_data,
   output reg [CTRL_WIDTH-1:0]             out_ctrl,
   output reg                              out_wr,
   input                                   out_rdy,
   
   // --- Misc
   input                                   clk,
   input                                   reset);
   
   //-------------------- Internal Parameters ------------------------
   localparam WAIT_FOR_INPUT_0 = 0 , // This is the default of case(state)
			  STORE_INPUT_0    = 1 ,
			  WAIT_FOR_INPUT_1 = 2 ,
			  NETWORK_CODING   = 3 ;
	
   localparam MODULE_HDRS      = 0 ,
			  WAIT_EOP         = 1 ;
			  
   
   //-------------------- Wires and regs ------------------------
   reg [1:0]							   state;
   reg      							   counter;
   
   reg                                     buffer_fifo_rd_en;
   reg                                     packet_fifo_0_rd_en;
   reg                                     packet_fifo_1_rd_en;
   
   reg									   in_wr_0;
   reg									   in_wr_1;
   
   reg [15:0]							   stored_packet_num;
   
   wire [DATA_WIDTH-1:0]                   buffer_fifo_data;
   wire [DATA_WIDTH-1:0]                   packet_fifo_0_data;
   wire [DATA_WIDTH-1:0]                   packet_fifo_1_data;
   
   //-------------------- modules ----------------------------------------------------------
   
   fallthrough_small_fifo #(.WIDTH(CTRL_WIDTH+DATA_WIDTH), .MAX_DEPTH_BITS(2))
     buffer_fifo
       (.din           ({in_ctrl, in_data}),   // Data in
        .wr_en         (in_wr),    // Write enable
        .rd_en         (buffer_fifo_rd_en),    // Read the next word
        .dout          ({buffer_fifo_ctrl, buffer_fifo_data}),
        .prog_full     (),
        .full          (),
        .nearly_full   (), // buffer_fifo_nearly_full
        .empty         (buffer_fifo_empty),
        .reset         (reset),
        .clk           (clk)
        );
   
   
   fallthrough_small_fifo #(.WIDTH(CTRL_WIDTH+DATA_WIDTH), .MAX_DEPTH_BITS(7))
     packet_fifo_0
       (.din           ({buffer_fifo_ctrl, buffer_fifo_data}),     // Data in
        .wr_en         (in_wr_0),                // Write enable
        .rd_en         (packet_fifo_0_rd_en),    // Read the next word
        .dout          ({packet_fifo_0_ctrl, packet_fifo_0_data}),
        .prog_full     (),
        .full          (),
        .nearly_full   (), // packet_fifo_0_nearly_full
        .empty         (packet_fifo_0_empty),
        .reset         (reset),
        .clk           (clk)
        );
   
   fallthrough_small_fifo #(.WIDTH(CTRL_WIDTH+DATA_WIDTH), .MAX_DEPTH_BITS(2))
     packet_fifo_1
       (.din           ({buffer_fifo_ctrl, buffer_fifo_data}),     // Data in
        .wr_en         (in_wr_1),                // Write enable
        .rd_en         (packet_fifo_1_rd_en),    // Read the next word
        .dout          ({packet_fifo_1_ctrl, packet_fifo_1_data}),
        .prog_full     (),
        .full          (),
        .nearly_full   (), // packet_fifo_1_nearly_full
        .empty         (packet_fifo_1_empty),
        .reset         (reset),
        .clk           (clk)
        );
   
   

   

   
   always @(posedge clk) begin
      if(reset) begin
        state <= 0;
		
      end
	  
	  else begin
	  //defaults
	  in_wr_0 <= 0;
	  in_wr_1 <= 0;
	  out_wr  <= 0;
		
		case(state)
		
			STORE_INPUT_0: begin
			  if(!buffer_fifo_empty) begin
				buffer_fifo_rd_en <= 1'b1;
			      case(counter)
				    
					MODULE_HDRS: begin
					  in_wr_0 <= 1'b1;
					  if(buffer_fifo_ctrl==0) begin
					    counter <= WAIT_EOP;
					  end
					end // case : MODULE_HDRS
					
					WAIT_EOP: begin
					  in_wr_0 <= 1'b1;
					  if(buffer_fifo_ctrl!=0) begin
					    counter <= 0;
						state   <= WAIT_FOR_INPUT_1;
					  end
					end // case : WAIT_EOP
					
				  endcase // case(counter)
			  end // if(!buffer_fifo_empty)
			end //case : STORE_INPUT_0
			
			WAIT_FOR_INPUT_1: begin
			
			end //case : WAIT_FOR_INPUT_1
		
			NETWORK_CODING: begin
			
			end //case : NETWORK_CODING
	  
			default: begin
				if(!buffer_fifo_empty) begin
				  buffer_fifo_rd_en <= 1'b1;
					if(buffer_fifo_ctrl == `IO_QUEUE_STAGE_NUM) begin
						if(buffer_fifo_data[31:16] == 16'd0 || buffer_fifo_data[31:16] == 16'd2) begin
							in_wr_0           <= 1'b1;
							stored_packet_num <= buffer_fifo_data[31:16];
							state             <= STORE_INPUT_0;
						end
					end // if(buffer_fifo_ctrl == `IO_QUEUE_STAGE_NUM)
					
					else begin
						out_ctrl <= buffer_fifo_ctrl;
						out_data <= buffer_fifo_data;
						out_wr   <= 1'b1;
					end
				end // if(!buffer_fifo_empty)
			end // case : WAIT_FOR_INPUT_0
		
		endcase // case(state)
	  
	  end // else
	  
   end // always @(posedge clk)
   
endmodule // XOR_network_coding
