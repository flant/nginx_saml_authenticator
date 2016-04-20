module Overcommit::Hook::PreCommit
  class BuildizerVerify < Base
    def run
      return :fail unless system("buildizer verify")
      :pass
    end
  end
end
